//! Replacement functions — task 2 implements all seven.
//! Stub for task 1's compile: provides sentinel_connect so the probe_self_test
//! in interpose.rs can reference the symbol.

/// Stub — task 2 replaces this with the full reentrancy-guarded implementation.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sentinel_connect(
    _s: libc::c_int,
    _addr: *const libc::sockaddr,
    _addrlen: libc::socklen_t,
) -> libc::c_int {
    -1
}
