//! Daemon-owned ptrace supervisor for issue #1 phase 3.
//!
//! The hook process must not run the wait loop: doing so would consume child
//! status that the package manager expects to reap. The daemon is already the
//! policy authority, so T3 children are created suspended and handed here for
//! attach/resume.

use std::ptr;
use tracing::{debug, error, info, warn};

#[derive(Debug, thiserror::Error)]
pub enum TraceError {
    #[error("ptrace attach pid={pid}: errno {errno}")]
    Attach { pid: libc::pid_t, errno: i32 },
    #[error("waitpid initial stop pid={pid}: errno {errno}")]
    InitialWait { pid: libc::pid_t, errno: i32 },
    #[error("tracee pid={pid} exited before attach completed")]
    ExitedBeforeAttach { pid: libc::pid_t },
    #[error("ptrace continue pid={pid}: errno {errno}")]
    Continue { pid: libc::pid_t, errno: i32 },
}

pub fn attach_and_supervise(
    pid: libc::pid_t,
    reason: String,
    target_path: String,
) -> Result<(), TraceError> {
    ptrace(libc::PT_ATTACHEXC, pid, ptr::null_mut(), 0)
        .map_err(|errno| TraceError::Attach { pid, errno })?;

    let mut status = 0;
    let waited = unsafe { libc::waitpid(pid, &mut status, libc::WUNTRACED) };
    if waited < 0 {
        return Err(TraceError::InitialWait {
            pid,
            errno: errno(),
        });
    }
    if libc::WIFEXITED(status) || libc::WIFSIGNALED(status) {
        return Err(TraceError::ExitedBeforeAttach { pid });
    }

    std::thread::spawn(move || supervise_loop(pid, reason, target_path, status));
    Ok(())
}

fn supervise_loop(
    pid: libc::pid_t,
    reason: String,
    target_path: String,
    first_status: libc::c_int,
) {
    info!(
        pid,
        reason = %reason,
        target_path = %target_path,
        "T3 ptrace supervisor attached"
    );

    if let Err(errno) = continue_tracee(pid, 0) {
        error!(pid, errno, "T3 ptrace initial continue failed");
        kill_tracee(pid);
        return;
    }
    unsafe {
        libc::kill(pid, libc::SIGCONT);
    }

    let mut status = first_status;
    loop {
        let waited = unsafe { libc::waitpid(pid, &mut status, 0) };
        if waited < 0 {
            let e = errno();
            if e != libc::ECHILD && e != libc::ESRCH {
                warn!(pid, errno = e, "T3 ptrace waitpid failed");
            }
            break;
        }
        if libc::WIFEXITED(status) || libc::WIFSIGNALED(status) {
            debug!(pid, status, "T3 ptrace tracee exited");
            break;
        }
        if libc::WIFSTOPPED(status) {
            let sig = libc::WSTOPSIG(status);
            let deliver = if sig == libc::SIGSTOP || sig == libc::SIGTRAP {
                0
            } else {
                sig
            };
            if let Err(e) = continue_tracee(pid, deliver) {
                warn!(pid, errno = e, "T3 ptrace continue failed");
                kill_tracee(pid);
                break;
            }
        }
    }
}

fn continue_tracee(pid: libc::pid_t, signal: libc::c_int) -> Result<(), i32> {
    ptrace(libc::PT_CONTINUE, pid, 1usize as *mut libc::c_char, signal)
}

fn kill_tracee(pid: libc::pid_t) {
    let _ = ptrace(libc::PT_KILL, pid, ptr::null_mut(), 0);
}

fn ptrace(
    request: libc::c_int,
    pid: libc::pid_t,
    addr: *mut libc::c_char,
    data: libc::c_int,
) -> Result<(), i32> {
    unsafe {
        *libc::__error() = 0;
        let rc = libc::ptrace(request, pid, addr, data);
        if rc == -1 {
            let e = errno();
            if e != 0 {
                return Err(e);
            }
        }
    }
    Ok(())
}

fn errno() -> i32 {
    unsafe { *libc::__error() }
}
