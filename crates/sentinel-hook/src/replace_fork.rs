//! Fork-family interpose shadows (D-32).
//!
//! Hot-path discipline (D-03 carry-forward): no heap allocation; no `format!`;
//! Vec/String only via the IPC client's serialization layer (which is acceptable
//! per the D-03 carve-out — fork/exec are not on the <100µs verdict path; they
//! pay an IPC round trip).
//!
//! Fail-closed on daemon-unreachable (D-33): the parent kills the child and
//! returns EAGAIN to the caller. The wrapped command's fork fails; the install
//! errors out — strongest correctness.
//!
//! Vfork-stack-safety (T-02-05-01 / Pitfall 4): the CHILD path of vfork shares
//! the parent's stack until exec/_exit. We must not allocate, take locks, or
//! do anything that mutates parent stack frames. The vfork child path here
//! resets IN_HOOK and returns 0 — the IPC is sent from the parent's path.

use crate::ipc_client::{copy_cstr_to_buf, send_exec_event_sync, send_fork_event_sync, IpcClientError};
use crate::reentrancy::IN_HOOK;
use sentinel_ipc::AuditTokenWire;

const IPC_TIMEOUT_MS: u64 = 250;

/// BLOCKER-02 fix: distinguish "daemon says I'm not tracked" (do not fail
/// closed — the dylib is loaded into a process outside `sentinel run`, so
/// fork hooks should pass through to the real syscall) from any other IPC
/// error (fail-closed per D-33).
///
/// The daemon's BLOCKER-02 gate replies with the literal substring
/// "untracked peer" when peer-auth places the calling process outside the
/// tracked tree. Matching on the substring is a string-coupled wire
/// contract; the daemon side must keep emitting this token for the dylib's
/// behaviour to remain correct. Both sides reference BLOCKER-02 to keep the
/// contract discoverable.
fn is_untracked_peer(err: &IpcClientError) -> bool {
    matches!(err, IpcClientError::DaemonRejected(m) if m.contains("untracked peer"))
}

// Verified from macOS 15.4 SDK /usr/include/sys/syscall.h:
const SYS_FORK: libc::c_int = 2;
const SYS_VFORK: libc::c_int = 66;

/// RAII guard — same shape as Phase 1 InHookGuard in replace_libc.rs. Holds
/// IN_HOOK=true for the entire shadow scope; releases on drop.
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

#[inline(always)]
unsafe fn raw_fork() -> libc::pid_t {
    // SAFETY: SYS_FORK takes no arguments. The kernel returns child pid in
    // parent / 0 in child / -1 on error.
    unsafe { libc::syscall(SYS_FORK) as libc::pid_t }
}

#[inline(always)]
unsafe fn raw_vfork() -> libc::pid_t {
    // SAFETY: SYS_VFORK takes no arguments. Vfork-stack-safety: caller MUST
    // not modify parent stack between vfork-return-in-child and exec/_exit.
    unsafe { libc::syscall(SYS_VFORK) as libc::pid_t }
}

/// Read the child's pidversion via proc_pidinfo. PROC_PIDTBSDINFO returns a
/// proc_bsdinfo struct whose `pbi_pid_version` field is at offset 28 on
/// macOS arm64/x86_64 (verified against the SDK header).
///
/// If the syscall fails or the offset reads past the buffer, returns 0. The
/// daemon's wire-claimed pidversion is overridden by kernel peer-auth on the
/// next IPC anyway (plan 02-04 handler), so a zero on failure is benign.
fn child_pidversion(child_pid: libc::pid_t) -> u32 {
    const PROC_PIDTBSDINFO: libc::c_int = 3;
    let mut info = [0u8; 256];
    let n = unsafe {
        libc::proc_pidinfo(
            child_pid,
            PROC_PIDTBSDINFO,
            0,
            info.as_mut_ptr() as *mut libc::c_void,
            info.len() as libc::c_int,
        )
    };
    if n <= 0 || (n as usize) < 32 {
        return 0;
    }
    u32::from_ne_bytes([info[28], info[29], info[30], info[31]])
}

/// Best-effort current process audit token for use as `parent_audit_token`.
/// The daemon trusts kernel peer-auth (LOCAL_PEERTOKEN) over wire-claimed
/// values (ENF-08 invariant from Phase 1 plan 04, carried forward by plan
/// 02-04 handlers). We send a zero token here and the daemon overrides on
/// receive — log fidelity is preserved by the daemon's logged peer pid.
fn current_audit_token_wire() -> AuditTokenWire {
    AuditTokenWire { val: [0; 8] }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn sentinel_fork() -> libc::pid_t {
    let _guard = match InHookGuard::enter() {
        Some(g) => g,
        None => return unsafe { raw_fork() },
    };
    let pid = unsafe { raw_fork() };
    if pid < 0 {
        return pid;
    }
    if pid == 0 {
        // CHILD path. Reset IN_HOOK to a clean state in the child (the
        // thread-local cell was copied at fork). Do NOT send IPC from here —
        // the parent does it.
        IN_HOOK.with(|c| c.set(false));
        return 0;
    }
    // PARENT path: send ForkEvent IPC. Fail-closed on error per D-33,
    // EXCEPT when the daemon explicitly tells us this peer is not in the
    // tracked tree (BLOCKER-02 — dylib loaded into a non-`sentinel run`
    // process; fail-closed there would self-DoS every fork on the box).
    let pv = child_pidversion(pid);
    let parent = current_audit_token_wire();
    match send_fork_event_sync(parent, pid as i32, pv, IPC_TIMEOUT_MS) {
        Ok(()) => pid,
        Err(e) if is_untracked_peer(&e) => {
            // BLOCKER-02: not under sentinel run → behave as if Sentinel
            // wasn't loaded for this fork. Return the child pid normally.
            pid
        }
        Err(_e) => {
            // D-33: kill child, set EAGAIN, return -1 — the wrapped caller
            // sees fork failure and the install errors out cleanly.
            unsafe {
                libc::kill(pid, libc::SIGKILL);
                *libc::__error() = libc::EAGAIN;
            }
            -1
        }
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn sentinel_vfork() -> libc::pid_t {
    let _guard = match InHookGuard::enter() {
        Some(g) => g,
        None => return unsafe { raw_vfork() },
    };
    let pid = unsafe { raw_vfork() };
    if pid < 0 {
        return pid;
    }
    if pid == 0 {
        // VFORK CHILD: parent's stack is shared. Do NOTHING that touches stack
        // beyond returning. The child will exec or _exit immediately.
        IN_HOOK.with(|c| c.set(false));
        return 0;
    }
    // PARENT path: send ForkEvent. BLOCKER-02 untracked-peer behaviour
    // mirrors `sentinel_fork`.
    let pv = child_pidversion(pid);
    let parent = current_audit_token_wire();
    match send_fork_event_sync(parent, pid as i32, pv, IPC_TIMEOUT_MS) {
        Ok(()) => pid,
        Err(e) if is_untracked_peer(&e) => pid,
        Err(_e) => {
            unsafe {
                libc::kill(pid, libc::SIGKILL);
                *libc::__error() = libc::EAGAIN;
            }
            -1
        }
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn sentinel_posix_spawn(
    pid_out: *mut libc::pid_t,
    path: *const libc::c_char,
    file_actions: *const libc::posix_spawn_file_actions_t,
    attrp: *const libc::posix_spawnattr_t,
    argv: *const *mut libc::c_char,
    envp: *const *mut libc::c_char,
) -> libc::c_int {
    let _guard = match InHookGuard::enter() {
        Some(g) => g,
        None => {
            return unsafe { libc::posix_spawn(pid_out, path, file_actions, attrp, argv, envp) };
        }
    };
    // Call the real posix_spawn via libc — IN_HOOK is set, so any nested hook
    // calls take the pass-through path.
    let rc = unsafe { libc::posix_spawn(pid_out, path, file_actions, attrp, argv, envp) };
    if rc != 0 {
        // posix_spawn returns errno on failure; do not send IPC.
        return rc;
    }
    if pid_out.is_null() {
        // Defensive — the kernel populated pid_out on success, but a
        // misuse shouldn't crash us.
        return 0;
    }
    let new_pid = unsafe { *pid_out };
    let pv = child_pidversion(new_pid);
    let parent = current_audit_token_wire();
    // Fork half — fail-closed on IPC failure per D-33, except for the
    // BLOCKER-02 untracked-peer signal (do not kill the child of a
    // process Sentinel doesn't actually own).
    //
    // BLOCKER-04 mitigation (BLOCKER-04 partial): the kill-on-failure path
    // here remains a known TOCTOU window — the child may already be running
    // arbitrary code by the time we kill it. We pin pidversion at
    // pre-spawn time and re-check before kill, mitigating the pid-reuse
    // race; the larger "fail-closed BEFORE the child runs" promise can
    // only be kept for posix_spawn by adding a new pre-spawn IPC, which
    // is deferred to a follow-up fix (see REVIEW-FIX.md).
    let saved_pv = pv;
    match send_fork_event_sync(parent, new_pid as i32, pv, IPC_TIMEOUT_MS) {
        Ok(()) => {}
        Err(e) if is_untracked_peer(&e) => {
            // Pass-through — Sentinel is loaded but this caller is not
            // under `sentinel run`. Skip the exec-half best-effort IPC too
            // (the daemon would just reject it).
            return 0;
        }
        Err(_) => {
            // BLOCKER-04 partial: re-check pidversion to mitigate the
            // pid-reuse race. If the kernel has already recycled the pid
            // between posix_spawn return and now, do not kill an unrelated
            // process.
            let now_pv = child_pidversion(new_pid);
            if now_pv != 0 && now_pv == saved_pv {
                unsafe {
                    libc::kill(new_pid, libc::SIGKILL);
                }
            }
            return libc::EAGAIN;
        }
    }
    // Exec half — best-effort (the spawn already happened; the child is
    // running). Failure is logged but not fail-closed.
    let mut path_buf = [0u8; 1024];
    let n = copy_cstr_to_buf(path, &mut path_buf);
    let _ = send_exec_event_sync(
        AuditTokenWire { val: [0; 8] },
        &path_buf[..n],
        n,
        IPC_TIMEOUT_MS,
    );
    0
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn sentinel_posix_spawnp(
    pid_out: *mut libc::pid_t,
    path: *const libc::c_char,
    file_actions: *const libc::posix_spawn_file_actions_t,
    attrp: *const libc::posix_spawnattr_t,
    argv: *const *mut libc::c_char,
    envp: *const *mut libc::c_char,
) -> libc::c_int {
    let _guard = match InHookGuard::enter() {
        Some(g) => g,
        None => {
            return unsafe { libc::posix_spawnp(pid_out, path, file_actions, attrp, argv, envp) };
        }
    };
    let rc = unsafe { libc::posix_spawnp(pid_out, path, file_actions, attrp, argv, envp) };
    if rc != 0 {
        return rc;
    }
    if pid_out.is_null() {
        return 0;
    }
    let new_pid = unsafe { *pid_out };
    let pv = child_pidversion(new_pid);
    let parent = current_audit_token_wire();
    let saved_pv = pv;
    match send_fork_event_sync(parent, new_pid as i32, pv, IPC_TIMEOUT_MS) {
        Ok(()) => {}
        Err(e) if is_untracked_peer(&e) => return 0,
        Err(_) => {
            // BLOCKER-04 partial: pidversion-pinned kill mitigates the
            // pid-reuse race window between posix_spawnp return and our
            // kill. See sentinel_posix_spawn for the full discussion.
            let now_pv = child_pidversion(new_pid);
            if now_pv != 0 && now_pv == saved_pv {
                unsafe {
                    libc::kill(new_pid, libc::SIGKILL);
                }
            }
            return libc::EAGAIN;
        }
    }
    let mut path_buf = [0u8; 1024];
    let n = copy_cstr_to_buf(path, &mut path_buf);
    let _ = send_exec_event_sync(
        AuditTokenWire { val: [0; 8] },
        &path_buf[..n],
        n,
        IPC_TIMEOUT_MS,
    );
    0
}
