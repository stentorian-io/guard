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

use crate::ipc_client::{copy_cstr_to_buf, send_exec_event_sync};
use crate::reentrancy::IN_HOOK;
use core::ffi::{c_char, c_int};
use sentinel_ipc::AuditTokenWire;

const IPC_TIMEOUT_MS: u64 = 250;
// Verified from macOS 15.4 SDK /usr/include/sys/syscall.h:
const SYS_EXECVE: libc::c_int = 59;

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

fn current_audit_token_wire() -> AuditTokenWire {
    AuditTokenWire { val: [0; 8] }
}

/// Send an ExecEvent IPC for `path`. Best-effort: errors are silently dropped
/// (the exec proceeds regardless — exec is not D-33's failure boundary).
fn report_exec(path: *const c_char) {
    let mut path_buf = [0u8; 1024];
    let n = copy_cstr_to_buf(path, &mut path_buf);
    let token = current_audit_token_wire();
    let _ = send_exec_event_sync(token, &path_buf[..n], n, IPC_TIMEOUT_MS);
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn sentinel_execve(
    path: *const c_char,
    argv: *const *const c_char,
    envp: *const *const c_char,
) -> c_int {
    let _guard = match InHookGuard::enter() {
        Some(g) => g,
        None => {
            // Already in a hook — bypass via raw syscall (avoids the
            // interpose chain). On success the syscall does not return; on
            // failure it returns -1 with errno set.
            return unsafe { libc::syscall(SYS_EXECVE, path, argv, envp) as c_int };
        }
    };
    report_exec(path);
    unsafe { libc::syscall(SYS_EXECVE, path, argv, envp) as c_int }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn sentinel_execvp(
    path: *const c_char,
    argv: *const *const c_char,
) -> c_int {
    let _guard = match InHookGuard::enter() {
        Some(g) => g,
        None => return unsafe { libc::execvp(path, argv) },
    };
    report_exec(path);
    unsafe { libc::execvp(path, argv) }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn sentinel_execv(path: *const c_char, argv: *const *const c_char) -> c_int {
    let _guard = match InHookGuard::enter() {
        Some(g) => g,
        None => return unsafe { libc::execv(path, argv) },
    };
    report_exec(path);
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
// execl* internally calls execve via direct branch (covered by sentinel_execve).
// ---------------------------------------------------------------------------

#[unsafe(no_mangle)]
pub unsafe extern "C" fn sentinel_execl(
    _path: *const c_char,
    _arg0: *const c_char,
) -> c_int {
    unsafe {
        *libc::__error() = libc::ENOSYS;
    }
    -1
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn sentinel_execlp(
    _path: *const c_char,
    _arg0: *const c_char,
) -> c_int {
    unsafe {
        *libc::__error() = libc::ENOSYS;
    }
    -1
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn sentinel_execle(
    _path: *const c_char,
    _arg0: *const c_char,
) -> c_int {
    unsafe {
        *libc::__error() = libc::ENOSYS;
    }
    -1
}
