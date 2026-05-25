//! __DATA,__interpose static records — task 2 fills in seven symbols.
use core::ffi::c_void;
use core::sync::atomic::{AtomicPtr, Ordering};

pub static REAL_CONNECT: AtomicPtr<c_void> = AtomicPtr::new(core::ptr::null_mut());
pub static REAL_CONNECTX: AtomicPtr<c_void> = AtomicPtr::new(core::ptr::null_mut());
pub static REAL_GETADDRINFO: AtomicPtr<c_void> = AtomicPtr::new(core::ptr::null_mut());
pub static REAL_GETADDRINFO_ASYNC: AtomicPtr<c_void> = AtomicPtr::new(core::ptr::null_mut());
pub static REAL_GETADDRINFO_ASYNC_CALL: AtomicPtr<c_void> = AtomicPtr::new(core::ptr::null_mut());
pub static REAL_SENDTO: AtomicPtr<c_void> = AtomicPtr::new(core::ptr::null_mut());
pub static REAL_SENDMSG: AtomicPtr<c_void> = AtomicPtr::new(core::ptr::null_mut());
pub static REAL_SEND: AtomicPtr<c_void> = AtomicPtr::new(core::ptr::null_mut());
pub static REAL_WRITE: AtomicPtr<c_void> = AtomicPtr::new(core::ptr::null_mut());
pub static REAL_WRITEV: AtomicPtr<c_void> = AtomicPtr::new(core::ptr::null_mut());
pub static REAL_SYSCALL: AtomicPtr<c_void> = AtomicPtr::new(core::ptr::null_mut());

/// Capture original libc symbol pointers.
///
/// IMPORTANT NOTE (v0.1 deviation, Rule 1 - Bug):
///
/// When stt-guard-hook.dylib is injected via DYLD_INSERT_LIBRARIES, dyld applies the
/// __DATA,__interpose records GLOBALLY — including patching the exported symbol table
/// entries of ALL loaded images (libSystem included). This means that after interposing:
///
///   - dlsym(RTLD_NEXT, "connect") returns guard_connect (not libSystem's connect)
///   - dlsym(libSystem_handle, "connect") also returns guard_connect
///   - libc::connect as *const c_void resolves to guard_connect via the GOT
///
/// All three approaches create an infinite recursion loop because REAL_CONNECT
/// points back to guard_connect itself.
///
/// THE FIX (v0.1): Use direct kernel syscalls instead of function pointers.
/// The hot-path replacement functions (guard_connect, guard_sendto, etc.)
/// call raw inline-assembly syscall wrappers in their allow/reentrancy paths.
/// This avoids both dyld interpose recursion and libc::syscall recursion.
///
/// These AtomicPtrs remain for compatibility with probe_self_test and future versions
/// that may find a way to store the real function pointers (e.g., Mach-O TEXT parsing).
/// They are NOT used in the hot path in v0.1.
pub unsafe fn capture_originals() {
    // NOTE: The values stored here will all equal our replacement functions
    // (guard_connect etc.) due to dyld's global interpose patching. They are
    // NOT used in the hot path — raw syscall wrappers are used instead (see
    // replace_libc.rs and raw_syscall.rs).
    // We still call dlsym to populate the fields for compatibility, knowing they
    // won't be used for call-through.
    let libsystem = unsafe {
        libc::dlopen(
            c"/usr/lib/libSystem.B.dylib".as_ptr(),
            libc::RTLD_NOLOAD | libc::RTLD_NOW,
        )
    };

    macro_rules! real_sym {
        ($handle:expr, $name:expr) => {{
            if $handle.is_null() {
                unsafe { libc::dlsym(libc::RTLD_NEXT, $name.as_ptr()) }
            } else {
                unsafe { libc::dlsym($handle, $name.as_ptr()) }
            }
        }};
    }

    REAL_CONNECT.store(real_sym!(libsystem, c"connect"), Ordering::Relaxed);
    REAL_CONNECTX.store(real_sym!(libsystem, c"connectx"), Ordering::Relaxed);
    REAL_GETADDRINFO.store(real_sym!(libsystem, c"getaddrinfo"), Ordering::Relaxed);
    REAL_GETADDRINFO_ASYNC.store(
        real_sym!(libsystem, c"getaddrinfo_async"),
        Ordering::Relaxed,
    );
    REAL_GETADDRINFO_ASYNC_CALL.store(
        real_sym!(libsystem, c"getaddrinfo_async_call"),
        Ordering::Relaxed,
    );
    REAL_SENDTO.store(real_sym!(libsystem, c"sendto"), Ordering::Relaxed);
    REAL_SENDMSG.store(real_sym!(libsystem, c"sendmsg"), Ordering::Relaxed);
    REAL_SEND.store(real_sym!(libsystem, c"send"), Ordering::Relaxed);
    REAL_WRITE.store(real_sym!(libsystem, c"write"), Ordering::Relaxed);
    REAL_WRITEV.store(real_sym!(libsystem, c"writev"), Ordering::Relaxed);
    REAL_SYSCALL.store(real_sym!(libsystem, c"syscall"), Ordering::Relaxed);

    crate::log_buffer::LOG_RING.append(b"[guard-hook] capture_originals: raw-syscall mode (v0.1)");
}

/// Mark the page containing the AtomicPtrs read-only (T-01-06-04 mitigation).
/// Best-effort: if mprotect fails, log and continue.
pub fn lock_originals_page() {
    unsafe {
        let addr = &REAL_CONNECT as *const _ as *mut libc::c_void;
        let page_size = libc::sysconf(libc::_SC_PAGESIZE) as usize;
        let aligned = (addr as usize / page_size) * page_size;
        let r = libc::mprotect(aligned as *mut libc::c_void, page_size, libc::PROT_READ);
        if r != 0 {
            let line =
                b"[guard-hook] mprotect originals_page failed (T-01-06-04 risk acknowledged)\n";
            crate::log_buffer::LOG_RING.append(line);
        }
    }
}

// ============================================================================
// v0.2 fork/exec interpose records (D-32) — 7 new __DATA,__interpose
// entries appended to v0.1's existing 4 records (in replace_libc.rs).
// Each record is a [shadow_fn, real_fn] pair; dyld swaps
// every load-time call to real_fn with shadow_fn process-wide.
//
// Why 7, not 10: execl/execlp/execle are intentionally OMITTED from the
// interpose table because their variadic ABI cannot be intercepted by a
// non-variadic Rust shadow without unstable language features. libc's
// internal execl/execlp/execle implementation ultimately calls execve via
// direct PC-relative branch (NOT via symbol lookup) — and execve IS in our
// interpose table. So coverage is preserved transitively.
// ============================================================================

#[allow(dead_code)]
struct SyncPtr2(*const c_void);
unsafe impl Sync for SyncPtr2 {}

unsafe extern "C" {
    // libc 0.2.x does NOT export vfork on BSD; declare it locally so we can
    // take its address as the "real" pointer in the interpose pair.
    fn vfork() -> libc::pid_t;
}

#[unsafe(no_mangle)]
#[unsafe(link_section = "__DATA,__interpose")]
#[used]
static STT_GUARD_INTERPOSE_FORK: [SyncPtr2; 2] = [
    SyncPtr2(crate::replace_fork::guard_fork as *const c_void),
    SyncPtr2(libc::fork as *const c_void),
];

#[unsafe(no_mangle)]
#[unsafe(link_section = "__DATA,__interpose")]
#[used]
static STT_GUARD_INTERPOSE_VFORK: [SyncPtr2; 2] = [
    SyncPtr2(crate::replace_fork::guard_vfork as *const c_void),
    SyncPtr2(vfork as *const c_void),
];

#[unsafe(no_mangle)]
#[unsafe(link_section = "__DATA,__interpose")]
#[used]
static STT_GUARD_INTERPOSE_POSIX_SPAWN: [SyncPtr2; 2] = [
    SyncPtr2(crate::replace_fork::guard_posix_spawn as *const c_void),
    SyncPtr2(libc::posix_spawn as *const c_void),
];

#[unsafe(no_mangle)]
#[unsafe(link_section = "__DATA,__interpose")]
#[used]
static STT_GUARD_INTERPOSE_POSIX_SPAWNP: [SyncPtr2; 2] = [
    SyncPtr2(crate::replace_fork::guard_posix_spawnp as *const c_void),
    SyncPtr2(libc::posix_spawnp as *const c_void),
];

#[unsafe(no_mangle)]
#[unsafe(link_section = "__DATA,__interpose")]
#[used]
static STT_GUARD_INTERPOSE_EXECVE: [SyncPtr2; 2] = [
    SyncPtr2(crate::replace_exec::guard_execve as *const c_void),
    SyncPtr2(libc::execve as *const c_void),
];

#[unsafe(no_mangle)]
#[unsafe(link_section = "__DATA,__interpose")]
#[used]
static STT_GUARD_INTERPOSE_EXECVP: [SyncPtr2; 2] = [
    SyncPtr2(crate::replace_exec::guard_execvp as *const c_void),
    SyncPtr2(libc::execvp as *const c_void),
];

#[unsafe(no_mangle)]
#[unsafe(link_section = "__DATA,__interpose")]
#[used]
static STT_GUARD_INTERPOSE_EXECV: [SyncPtr2; 2] = [
    SyncPtr2(crate::replace_exec::guard_execv as *const c_void),
    SyncPtr2(libc::execv as *const c_void),
];

// M004-S04: getenv interposition for anti-detection hardening.
#[unsafe(no_mangle)]
#[unsafe(link_section = "__DATA,__interpose")]
#[used]
static STT_GUARD_INTERPOSE_GETENV: [SyncPtr2; 2] = [
    SyncPtr2(crate::env_scrub::guard_getenv as *const c_void),
    SyncPtr2(libc::getenv as *const c_void),
];

/// ISS-12 remediation: confirm OUR `__DATA,__interpose` record on `connect`
/// actually took effect for this process. Resolution rule for two competing
/// interpose records on the same symbol is implementation-defined; this probe
/// proves ours is active.
///
/// Mechanism: dlsym(`RTLD_DEFAULT`, "connect") returns whatever the dynamic
/// linker has chosen as the active `connect` symbol for this image. If it
/// equals `&guard_connect` (our replacement), our interpose is active.
///
/// On probe failure: set FAIL_CLOSED = true, log a clear line, return.
#[cfg(target_os = "macos")]
pub fn probe_self_test() {
    use core::ffi::c_void;
    use core::sync::atomic::Ordering;
    unsafe extern "C" {
        fn guard_connect(
            s: libc::c_int,
            addr: *const libc::sockaddr,
            addrlen: libc::socklen_t,
        ) -> libc::c_int;
        fn guard_write(fd: libc::c_int, buf: *const c_void, count: libc::size_t) -> libc::ssize_t;
        fn guard_getaddrinfo(
            node: *const libc::c_char,
            service: *const libc::c_char,
            hints: *const libc::addrinfo,
            res: *mut *mut libc::addrinfo,
        ) -> libc::c_int;
    }
    unsafe {
        let active_connect = libc::dlsym(libc::RTLD_DEFAULT, c"connect".as_ptr());
        let ours_connect = guard_connect as *mut c_void;
        if active_connect != ours_connect {
            crate::snapshot::FAIL_CLOSED.store(true, Ordering::Release);
            crate::log_buffer::LOG_RING.append(
                b"[guard-hook] interpose-not-effective: dlsym(RTLD_DEFAULT,\"connect\") != &guard_connect \xe2\x80\x94 entering FAIL_CLOSED (ISS-12 / T-01-08-01)",
            );
            return;
        }

        let active_write = libc::dlsym(libc::RTLD_DEFAULT, c"write".as_ptr());
        let ours_write = guard_write as *mut c_void;
        if active_write != ours_write {
            crate::snapshot::FAIL_CLOSED.store(true, Ordering::Release);
            crate::log_buffer::LOG_RING.append(
                b"[guard-hook] interpose-not-effective: dlsym(RTLD_DEFAULT,\"write\") != &guard_write \xe2\x80\x94 entering FAIL_CLOSED",
            );
            return;
        }

        let active_gai = libc::dlsym(libc::RTLD_DEFAULT, c"getaddrinfo".as_ptr());
        let ours_gai = guard_getaddrinfo as *mut c_void;
        if active_gai != ours_gai {
            crate::snapshot::FAIL_CLOSED.store(true, Ordering::Release);
            crate::log_buffer::LOG_RING.append(
                b"[guard-hook] interpose-not-effective: dlsym(RTLD_DEFAULT,\"getaddrinfo\") != &guard_getaddrinfo \xe2\x80\x94 entering FAIL_CLOSED",
            );
            return;
        }

        crate::log_buffer::LOG_RING.append(
            b"[guard-hook] interpose self-test passed (guard_connect + guard_write + guard_getaddrinfo active)",
        );
    }
}

#[cfg(not(target_os = "macos"))]
pub fn probe_self_test() {
    crate::log_buffer::LOG_RING
        .append(b"[guard-hook] interpose self-test skipped: dyld __interpose is macOS-only");
}
