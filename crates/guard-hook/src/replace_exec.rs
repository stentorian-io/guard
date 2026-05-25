//! Exec-family interpose shadows (D-32).
//!
//! exec succeeds by replacing the process image — the function does not return
//! on success. On failure it returns -1 with errno set. We send an ExecEvent
//! IPC BEFORE the syscall (best-effort: failure is logged, not fail-closed;
//! the exec still proceeds — exec is not the boundary that D-33 protects).
//!
//! Variadic execl/execlp/execle: the dyld interpose mechanism cannot redirect
//! variadic calls to a non-variadic Rust shadow without unstable language
//! features. We DO NOT add interpose records for the variadic family — instead
//! we rely on the fact that libc's internal execl/execlp/execle implementation
//! ultimately calls execve via direct PC-relative branch (NOT via symbol
//! lookup). dyld's __DATA,__interpose patching of execve catches that call.
//! See `interpose.rs` for the comment block describing this trade-off.
//!
//! For defense-in-depth, the variadic shadows below are defined with non-
//! variadic ABI and immediately set `errno = ENOSYS` and return -1. They are
//! NEVER reached in practice (no interpose record points at them); they exist
//! only to satisfy any caller that tries `dlsym("execl")` after dyld's
//! interpose patching has rewritten their address.

use crate::exec_policy::{self, ExecDecision};
use crate::ipc_client::{copy_cstr_to_buf, send_exec_blocked, send_exec_event_sync};
use crate::macho_scan::BlockReason;
use crate::raw_syscall;
use crate::reentrancy::IN_HOOK;
use core::ffi::{c_char, c_int};
use guard_ipc::AuditTokenWire;
use guard_os::errno::set_errno;

const IPC_TIMEOUT_MS: u64 = 250;

struct InHookGuard {
    _priv: (),
}
impl InHookGuard {
    #[inline]
    fn enter() -> Option<Self> {
        if IN_HOOK.with(|c| c.replace(true)) {
            None
        } else {
            Some(Self { _priv: () })
        }
    }
}
impl Drop for InHookGuard {
    #[inline]
    fn drop(&mut self) {
        IN_HOOK.with(|c| c.set(false));
    }
}

/// BLOCKER-07 fix: see `replace_fork.rs::current_audit_token_wire` for the
/// rationale. The wire-claimed token now carries `getpid()` in `val[5]` and
/// `getppid()` in `val[6]` as advisory hints; the daemon's authoritative
/// parent identity remains the kernel-sourced peer token (ENF-08).
fn current_audit_token_wire() -> AuditTokenWire {
    // SAFETY: getpid()/getppid() are async-signal-safe and always succeed.
    let pid = unsafe { libc::getpid() } as u32;
    let ppid = unsafe { libc::getppid() } as u32;
    let mut val = [0u32; 8];
    val[5] = pid;
    val[6] = ppid;
    AuditTokenWire { val }
}

fn report_exec_blocked(path: *const c_char, reason: BlockReason) {
    let mut path_buf = [0u8; 1024];
    let n = copy_cstr_to_buf(path, &mut path_buf);
    let token = current_audit_token_wire();
    send_exec_blocked(token, &path_buf[..n], reason.as_str());
}

fn block_exec_trace_required(
    path: *const c_char,
    reason: crate::macho_scan::SuspiciousReason,
) -> c_int {
    let mut path_buf = [0u8; 1024];
    let n = copy_cstr_to_buf(path, &mut path_buf);
    let line = format!(
        "[guard-hook] T3 fail-closed for exec-family call reason={} path={}",
        reason.as_str(),
        String::from_utf8_lossy(&path_buf[..n])
    );
    crate::log_buffer::LOG_RING.append(line.as_bytes());
    set_errno(libc::EACCES);
    -1
}

/// Send an ExecEvent IPC for `path`. Best-effort: errors are silently dropped
/// (the exec proceeds regardless — exec is not D-33's failure boundary).
///
/// `pm_env` is captured by the caller from envp (or `**environ`) before the
/// real exec replaces the process image. Wired in by Task 3 of
/// quick-260508-et9 (BLOCKER #1).
fn report_exec(path: *const c_char, pm_env: Vec<(String, String)>) {
    let mut path_buf = [0u8; 1024];
    let n = copy_cstr_to_buf(path, &mut path_buf);
    let token = current_audit_token_wire();
    let _ = send_exec_event_sync(token, &path_buf[..n], n, pm_env, IPC_TIMEOUT_MS);
}

#[cfg_attr(target_os = "macos", unsafe(no_mangle))]
#[cfg_attr(target_os = "linux", unsafe(export_name = "execve"))]
pub unsafe extern "C" fn guard_execve(
    path: *const c_char,
    argv: *const *const c_char,
    envp: *const *const c_char,
) -> c_int {
    let _guard = match InHookGuard::enter() {
        Some(g) => g,
        None => {
            return unsafe { raw_syscall::raw_execve(path, argv, envp) };
        }
    };
    match exec_policy::check_exec_target(path) {
        ExecDecision::Block(reason) => {
            report_exec_blocked(path, reason);
            set_errno(libc::EACCES);
            return -1;
        }
        ExecDecision::Trace(reason) => return block_exec_trace_required(path, reason),
        ExecDecision::Allow => {}
    }
    let pm_env = unsafe { crate::pm_env_filter::extract_pm_env_from_envp(envp) };
    report_exec(path, pm_env);
    unsafe { raw_syscall::raw_execve(path, argv, envp) }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn guard_execvp(path: *const c_char, argv: *const *const c_char) -> c_int {
    let _guard = match InHookGuard::enter() {
        Some(g) => g,
        None => return unsafe { libc::execvp(path, argv) },
    };
    match exec_policy::check_exec_target(path) {
        ExecDecision::Block(reason) => {
            report_exec_blocked(path, reason);
            set_errno(libc::EACCES);
            return -1;
        }
        ExecDecision::Trace(reason) => return block_exec_trace_required(path, reason),
        ExecDecision::Allow => {}
    }
    let pm_env = crate::pm_env_filter::extract_pm_env_from_environ();
    report_exec(path, pm_env);
    unsafe { libc::execvp(path, argv) }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn guard_execv(path: *const c_char, argv: *const *const c_char) -> c_int {
    let _guard = match InHookGuard::enter() {
        Some(g) => g,
        None => return unsafe { libc::execv(path, argv) },
    };
    match exec_policy::check_exec_target(path) {
        ExecDecision::Block(reason) => {
            report_exec_blocked(path, reason);
            set_errno(libc::EACCES);
            return -1;
        }
        ExecDecision::Trace(reason) => return block_exec_trace_required(path, reason),
        ExecDecision::Allow => {}
    }
    let pm_env = crate::pm_env_filter::extract_pm_env_from_environ();
    report_exec(path, pm_env);
    unsafe { libc::execv(path, argv) }
}

// ---------------------------------------------------------------------------
// Variadic execl/execlp/execle defense-in-depth shadows.
//
// These are NOT reached via dyld interpose (no interpose record points at
// them — see interpose.rs). They exist only to satisfy any caller that tries
// `dlsym("execl")` after dyld's global interpose patching has rewritten the
// symbol's resolved address. Setting errno=ENOSYS and returning -1 is safer
// than silently dispatching with no event reported.
//
// The non-variadic Rust signature here is intentional: implementing the
// variadic signature requires unstable Rust features (varargs in extern "C"
// fn body). We accept that callers reaching these by direct symbol resolution
// see ENOSYS — which they shouldn't reach in the first place because libc's
// execl* internally calls execve via direct branch (covered by guard_execve).
// ---------------------------------------------------------------------------

#[unsafe(no_mangle)]
pub unsafe extern "C" fn guard_execl(_path: *const c_char, _arg0: *const c_char) -> c_int {
    set_errno(libc::ENOSYS);
    -1
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn guard_execlp(_path: *const c_char, _arg0: *const c_char) -> c_int {
    set_errno(libc::ENOSYS);
    -1
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn guard_execle(_path: *const c_char, _arg0: *const c_char) -> c_int {
    set_errno(libc::ENOSYS);
    -1
}
