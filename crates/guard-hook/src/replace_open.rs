//! open/openat interpose for persistence-path monitoring (M003-S04).
//!
//! Detects when a process under `stt-guard wrap` opens a file in a macOS
//! persistence location (`LaunchAgents`, cron tabs, login items) with write
//! flags. The open is NOT blocked — a fire-and-forget `PersistenceWrite` IPC
//! message is sent to the daemon for forensic logging, then the real open
//! proceeds.

use crate::ipc_client::{self, copy_cstr_to_buf};
use crate::persistence_paths;
use crate::reentrancy::IN_HOOK;
use core::ffi::{c_char, c_int};
use guard_ipc::AuditTokenWire;

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

fn home_bytes() -> &'static [u8] {
    use std::sync::OnceLock;
    static HOME: OnceLock<Vec<u8>> = OnceLock::new();
    HOME.get_or_init(|| {
        let p = unsafe { libc::getenv(c"HOME".as_ptr()) };
        if p.is_null() {
            Vec::new()
        } else {
            let cs = unsafe { core::ffi::CStr::from_ptr(p) };
            cs.to_bytes().to_vec()
        }
    })
}

#[inline]
fn is_write_flags(oflag: c_int) -> bool {
    let accmode = oflag & libc::O_ACCMODE;
    accmode == libc::O_WRONLY
        || accmode == libc::O_RDWR
        || (oflag & libc::O_CREAT) != 0
        || (oflag & libc::O_TRUNC) != 0
}

fn maybe_report_persistence_write(path_ptr: *const c_char, oflag: c_int) {
    if !is_write_flags(oflag) {
        return;
    }
    if ipc_client::daemon_socket_path().is_none() {
        return;
    }
    let mut buf = [0u8; 1024];
    let n = unsafe { copy_cstr_to_buf(path_ptr, &mut buf) };
    if n == 0 {
        return;
    }
    let path = &buf[..n];
    let home = home_bytes();
    if let Some(category) = persistence_paths::classify_persistence_path(path, home) {
        let process_id = u32::try_from(unsafe { libc::getpid() }).unwrap_or(0);
        let parent_process_id = u32::try_from(unsafe { libc::getppid() }).unwrap_or(0);
        let mut token_val = [0u32; 8];
        token_val[5] = process_id;
        token_val[6] = parent_process_id;
        let audit_token = AuditTokenWire { val: token_val };
        ipc_client::send_persistence_write(audit_token, path, category);
    }
}

#[unsafe(no_mangle)]
/// Interposed `open(2)` entrypoint.
///
/// # Safety
///
/// `path` must satisfy the platform `open(2)` contract.
pub unsafe extern "C" fn guard_open(
    path: *const c_char,
    oflag: c_int,
    mode: libc::mode_t,
) -> c_int {
    let Some(_guard) = InHookGuard::enter() else {
        return unsafe { crate::raw_syscall::raw_open(path, oflag, mode) };
    };
    maybe_report_persistence_write(path, oflag);
    unsafe { crate::raw_syscall::raw_open(path, oflag, mode) }
}

#[unsafe(no_mangle)]
/// Interposed `openat(2)` entrypoint.
///
/// # Safety
///
/// `path` must satisfy the platform `openat(2)` contract.
pub unsafe extern "C" fn guard_openat(
    dirfd: c_int,
    path: *const c_char,
    oflag: c_int,
    mode: libc::mode_t,
) -> c_int {
    let Some(_guard) = InHookGuard::enter() else {
        return unsafe { crate::raw_syscall::raw_openat(dirfd, path, oflag, mode) };
    };
    if !path.is_null() {
        let first = unsafe { *path.cast::<u8>() };
        if first == b'/' {
            maybe_report_persistence_write(path, oflag);
        }
    }
    unsafe { crate::raw_syscall::raw_openat(dirfd, path, oflag, mode) }
}

// ---- THE INTERPOSE RECORDS ----

// open/openat interpose disabled: on macOS 26+, interposing open() from a
// Rust cdylib triggers dispatch_once reentrancy in Network.framework during
// getaddrinfo → nw_path_libinfo_path_check → os_log_create →
// _os_trace_read_file_at → open(). The crash occurs even when guard_open
// is a pure raw-syscall passthrough — the issue is in dyld's global symbol
// patching interacting with Network.framework's initialization chain, not
// in our hook logic. A minimal C dylib with the same open interpose does
// NOT crash, suggesting the Rust cdylib's binary structure (additional
// __mod_init_func entries, larger __DATA segment, thread-local storage
// descriptors) changes dyld's initialization order in a way that makes the
// dispatch_once reentrancy window reachable.
//
// Persistence-write monitoring (M003-S04) is now handled daemon-side via
// kqueue EVFILT_VNODE directory watching (persistence_watcher.rs). The
// daemon monitors persistence directories directly, eliminating the need
// for hook-side open() interposition.
//
// #[unsafe(no_mangle)]
// #[unsafe(link_section = "__DATA,__interpose")]
// #[used]
// static STT_GUARD_INTERPOSE_OPEN: [SyncPtr; 2] = [
//     SyncPtr(guard_open as *const c_void),
//     SyncPtr(open as *const c_void),
// ];
//
// #[unsafe(no_mangle)]
// #[unsafe(link_section = "__DATA,__interpose")]
// #[used]
// static STT_GUARD_INTERPOSE_OPENAT: [SyncPtr; 2] = [
//     SyncPtr(guard_openat as *const c_void),
//     SyncPtr(openat as *const c_void),
// ];
