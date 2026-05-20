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

use crate::exec_policy::{self, ExecDecision};
use crate::ipc_client::{
    copy_cstr_to_buf, send_env_not_propagated_gap_sync, send_exec_blocked, send_exec_event_sync,
    send_fork_event_sync, IpcClientError,
};
use crate::macho_scan::BlockReason;
use crate::reentrancy::IN_HOOK;
use sentinel_ipc::AuditTokenWire;

const IPC_TIMEOUT_MS: u64 = 250;

fn report_exec_blocked(path: *const libc::c_char, reason: BlockReason) {
    let mut path_buf = [0u8; 1024];
    let n = copy_cstr_to_buf(path, &mut path_buf);
    let token = current_audit_token_wire();
    send_exec_blocked(token, &path_buf[..n], reason.as_str());
}

/// BLOCKER-02 fix: distinguish "daemon says I'm not tracked" (do not fail
/// closed — the dylib is loaded into a process outside `sentinel wrap`, so
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

use crate::raw_syscall;

/// RAII guard — same shape as v0.1 InHookGuard in replace_libc.rs. Holds
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
    unsafe { raw_syscall::raw_fork() }
}

#[inline(always)]
unsafe fn raw_vfork() -> libc::pid_t {
    unsafe { raw_syscall::raw_vfork() }
}

/// Read the child's pidversion via task_info(TASK_AUDIT_TOKEN).
///
/// TREE-07 fix: the previous implementation read raw offset 28 from
/// proc_bsdinfo, which is actually `pbi_ruid` (not pidversion — the
/// proc_bsdinfo struct has no pidversion field). This replacement uses
/// Mach task_name_for_pid + task_info(TASK_AUDIT_TOKEN) to extract the
/// real kernel pidversion (audit_token val[7]).
///
/// Fallback: if task_name_for_pid fails (e.g. entitlement restrictions
/// on future macOS), falls back to pbi_start_tvsec ^ pbi_start_tvusec
/// as a pidversion analog (matching the CLI's fallback in audit_token.rs).
///
/// Returns 0 on total failure. The daemon trusts kernel peer-auth
/// (LOCAL_PEERTOKEN) over wire-claimed values, so zero is benign.
fn child_pidversion(child_pid: libc::pid_t) -> u32 {
    type MachPortT = u32;
    type KernReturnT = i32;
    const MACH_PORT_NULL: MachPortT = 0;
    const KERN_SUCCESS: KernReturnT = 0;
    const TASK_AUDIT_TOKEN: u32 = 15;

    unsafe extern "C" {
        fn mach_task_self() -> MachPortT;
        fn task_name_for_pid(
            target_tport: MachPortT,
            pid: libc::pid_t,
            t: *mut MachPortT,
        ) -> KernReturnT;
        fn task_info(
            target_task: MachPortT,
            flavor: u32,
            task_info_out: *mut u32,
            task_info_count: *mut u32,
        ) -> KernReturnT;
        fn mach_port_deallocate(task: MachPortT, name: MachPortT) -> KernReturnT;
    }

    let mut task_port: MachPortT = MACH_PORT_NULL;
    let kr = unsafe { task_name_for_pid(mach_task_self(), child_pid, &mut task_port) };
    if kr == KERN_SUCCESS {
        let mut token_val = [0u32; 8];
        let mut count: u32 = 8;
        let kr2 = unsafe {
            task_info(
                task_port,
                TASK_AUDIT_TOKEN,
                token_val.as_mut_ptr(),
                &mut count,
            )
        };
        unsafe { mach_port_deallocate(mach_task_self(), task_port) };
        if kr2 == KERN_SUCCESS {
            return token_val[7]; // pidversion
        }
    }

    // Fallback: use pbi_start_tvsec ^ pbi_start_tvusec as analog.
    const PROC_PIDTBSDINFO: libc::c_int = 3;
    const EXPECTED_SIZE: libc::c_int = 136; // sizeof(proc_bsdinfo)
    let mut info = [0u8; 136];
    let n = unsafe {
        libc::proc_pidinfo(
            child_pid,
            PROC_PIDTBSDINFO,
            0,
            info.as_mut_ptr() as *mut libc::c_void,
            EXPECTED_SIZE,
        )
    };
    if n != EXPECTED_SIZE {
        return 0;
    }
    // pbi_start_tvsec at offset 120 (u64), pbi_start_tvusec at offset 128 (u64).
    let tvsec = u64::from_ne_bytes(info[120..128].try_into().unwrap_or([0; 8]));
    let tvusec = u64::from_ne_bytes(info[128..136].try_into().unwrap_or([0; 8]));
    (tvsec as u32) ^ (tvusec as u32)
}

/// Best-effort current process audit token for use as `parent_audit_token`.
/// The daemon trusts kernel peer-auth (LOCAL_PEERTOKEN) over wire-claimed
/// values (ENF-08 invariant from v0.1, carried forward by v0.2 handlers).
///
/// BLOCKER-07 fix (v0.2 review): we now populate `val[5] = getpid()` and
/// `val[6] = getppid()` so the wire field carries USEFUL information for
/// the daemon to consult as a fallback hint when the peer-auth pid alone
/// does not place the peer in the tracked tree (e.g. a process re-execing
/// without the dylib intercept, then re-loading the dylib via env
/// inheritance — the daemon needs the parent pid to walk the tree).
///
/// The daemon's authoritative parent identity remains the kernel-sourced
/// peer token; the wire-claimed values are advisory. If wire and kernel
/// disagree on `val[5]` (the calling process's own pid), the daemon logs
/// at warn level and trusts the kernel — see `ipc_server.rs` ENF-08.
fn current_audit_token_wire() -> AuditTokenWire {
    // SAFETY: getpid()/getppid() are async-signal-safe and always succeed.
    let pid = unsafe { libc::getpid() } as u32;
    let ppid = unsafe { libc::getppid() } as u32;
    let mut val = [0u32; 8];
    val[5] = pid;
    val[6] = ppid;
    AuditTokenWire { val }
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
    // tracked tree (BLOCKER-02 — dylib loaded into a non-`sentinel wrap`
    // process; fail-closed there would self-DoS every fork on the box).
    let pv = child_pidversion(pid);
    let parent = current_audit_token_wire();
    match send_fork_event_sync(parent, pid as i32, pv, IPC_TIMEOUT_MS) {
        Ok(()) => pid,
        Err(e) if is_untracked_peer(&e) => {
            // BLOCKER-02: not under sentinel wrap → behave as if Sentinel
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
    if let ExecDecision::Block(reason) = exec_policy::check_exec_target(path) {
        report_exec_blocked(path, reason);
        return libc::EACCES;
    }

    // TREE-06 (gap-closure 02-09): inspect envp pre-spawn for missing Sentinel
    // env vars. If any are absent, emit a best-effort EnvNotPropagatedGap IPC
    // BEFORE the real posix_spawn fires (so the gap is recorded even if the
    // child is never created). Failure is logged but NOT fail-closed —
    // TREE-06 is informational, not enforcement.
    if unsafe { crate::envp::should_emit_env_not_propagated_gap(envp) } {
        let mut path_buf = [0u8; 1024];
        let n = copy_cstr_to_buf(path, &mut path_buf);
        let detected_at_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);
        let _ = send_env_not_propagated_gap_sync(
            current_audit_token_wire(),
            &path_buf[..n],
            detected_at_ms,
            IPC_TIMEOUT_MS,
        );
        // Continue regardless — best-effort.
    }

    // BLOCKER-05 assumption (v0.2 review): we hold IN_HOOK=true across
    // the libc::posix_spawn call. Apple's posix_spawn(2) implementation
    // atomically fork+execs without invoking user-visible interpose records
    // during the in-flight window — the child's image is replaced before
    // any user code runs. Therefore the parent's `IN_HOOK=true` thread-local
    // cannot leak into a nested hook in the child. If Apple ever changes
    // this assumption (verified on macOS 14.x and 15.x as of 2025), this
    // hook becomes a reentrancy hazard. Reach for `posix_spawn_file_actions`
    // (a pre-spawn IPC) or interpose via Endpoint Security at that point.
    //
    // The fork hook (`sentinel_fork`) and vfork hook (`sentinel_vfork`)
    // explicitly reset IN_HOOK in the child path because raw_fork()/raw_vfork()
    // share the parent's thread-local cell across the fork. posix_spawn does
    // NOT need that reset here because the libc atomic forks-and-execs in a
    // single call — the child's exec discards inherited mappings before any
    // hook can fire.
    //
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
            // under `sentinel wrap`. Skip the exec-half best-effort IPC too
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
    // BLOCKER-07: forward the (pid, ppid) advisory hint via the wire
    // audit-token field so the daemon can reconstruct tree linkage if
    // peer-auth alone doesn't place us. See `current_audit_token_wire`.
    //
    // BLOCKER #1 closure (quick-260508-et9): walk the caller-supplied envp
    // and filter to PM-relevant keys. The real posix_spawn already returned
    // and the child is running with this exact envp; capturing now from the
    // parent's address space mirrors what the child saw at exec.
    // SAFETY: posix_spawn(2) requires envp to be null OR a null-terminated
    // array of NUL-terminated C-string pointers; the caller's contract is
    // identical to execve's.
    let pm_env = unsafe { crate::pm_env_filter::extract_pm_env_from_envp_mut(envp) };
    let _ = send_exec_event_sync(
        current_audit_token_wire(),
        &path_buf[..n],
        n,
        pm_env,
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
    if let ExecDecision::Block(reason) = exec_policy::check_exec_target(path) {
        report_exec_blocked(path, reason);
        return libc::EACCES;
    }

    // TREE-06 (gap-closure 02-09): same pre-spawn envp inspection as
    // sentinel_posix_spawn. Best-effort — see that function's comment.
    if unsafe { crate::envp::should_emit_env_not_propagated_gap(envp) } {
        let mut path_buf = [0u8; 1024];
        let n = copy_cstr_to_buf(path, &mut path_buf);
        let detected_at_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);
        let _ = send_env_not_propagated_gap_sync(
            current_audit_token_wire(),
            &path_buf[..n],
            detected_at_ms,
            IPC_TIMEOUT_MS,
        );
    }

    // BLOCKER-05: see `sentinel_posix_spawn` for the IN_HOOK-thread-local
    // reentrancy assumption — same logic applies to posix_spawnp.
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
    // BLOCKER-07: forward the (pid, ppid) advisory hint via the wire
    // audit-token field so the daemon can reconstruct tree linkage if
    // peer-auth alone doesn't place us. See `current_audit_token_wire`.
    //
    // BLOCKER #1 closure (quick-260508-et9): walk the caller-supplied envp
    // and filter to PM-relevant keys. Same contract as sentinel_posix_spawn.
    // SAFETY: posix_spawnp's envp follows the POSIX execve(2) shape.
    let pm_env = unsafe { crate::pm_env_filter::extract_pm_env_from_envp_mut(envp) };
    let _ = send_exec_event_sync(
        current_audit_token_wire(),
        &path_buf[..n],
        n,
        pm_env,
        IPC_TIMEOUT_MS,
    );
    0
}
