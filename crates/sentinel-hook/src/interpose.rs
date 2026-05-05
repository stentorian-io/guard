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

pub unsafe fn capture_originals() {
    REAL_CONNECT.store(
        unsafe { libc::dlsym(libc::RTLD_NEXT, c"connect".as_ptr()) },
        Ordering::Relaxed,
    );
    REAL_CONNECTX.store(
        unsafe { libc::dlsym(libc::RTLD_NEXT, c"connectx".as_ptr()) },
        Ordering::Relaxed,
    );
    REAL_GETADDRINFO.store(
        unsafe { libc::dlsym(libc::RTLD_NEXT, c"getaddrinfo".as_ptr()) },
        Ordering::Relaxed,
    );
    REAL_GETADDRINFO_ASYNC.store(
        unsafe { libc::dlsym(libc::RTLD_NEXT, c"getaddrinfo_async".as_ptr()) },
        Ordering::Relaxed,
    );
    REAL_GETADDRINFO_ASYNC_CALL.store(
        unsafe { libc::dlsym(libc::RTLD_NEXT, c"getaddrinfo_async_call".as_ptr()) },
        Ordering::Relaxed,
    );
    REAL_SENDTO.store(
        unsafe { libc::dlsym(libc::RTLD_NEXT, c"sendto".as_ptr()) },
        Ordering::Relaxed,
    );
    REAL_SENDMSG.store(
        unsafe { libc::dlsym(libc::RTLD_NEXT, c"sendmsg".as_ptr()) },
        Ordering::Relaxed,
    );
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
                b"[sentinel-hook] mprotect originals_page failed (T-01-06-04 risk acknowledged)\n";
            crate::log_buffer::LOG_RING.append(line);
        }
    }
}

/// ISS-12 remediation: confirm OUR `__DATA,__interpose` record on `connect`
/// actually took effect for this process. Resolution rule for two competing
/// interpose records on the same symbol is implementation-defined; this probe
/// proves ours is active.
///
/// Mechanism: dlsym(`RTLD_DEFAULT`, "connect") returns whatever the dynamic
/// linker has chosen as the active `connect` symbol for this image. If it
/// equals `&sentinel_connect` (our replacement), our interpose is active.
///
/// On probe failure: set FAIL_CLOSED = true, log a clear line, return.
pub fn probe_self_test() {
    use core::ffi::c_void;
    use core::sync::atomic::Ordering;
    unsafe extern "C" {
        // Reference to our own replacement function in replace_libc.rs.
        fn sentinel_connect(
            s: libc::c_int,
            addr: *const libc::sockaddr,
            addrlen: libc::socklen_t,
        ) -> libc::c_int;
    }
    unsafe {
        let active = libc::dlsym(libc::RTLD_DEFAULT, c"connect".as_ptr());
        let ours = sentinel_connect as *mut c_void;
        if active != ours {
            crate::snapshot::FAIL_CLOSED.store(true, Ordering::Release);
            let line = b"[sentinel-hook] interpose-not-effective: dlsym(RTLD_DEFAULT,\"connect\") != &sentinel_connect \xe2\x80\x94 entering FAIL_CLOSED (ISS-12 / T-01-08-01)";
            crate::log_buffer::LOG_RING.append(line);
        } else {
            let line = b"[sentinel-hook] interpose self-test passed (sentinel_connect is the active connect symbol)";
            crate::log_buffer::LOG_RING.append(line);
        }
    }
}
