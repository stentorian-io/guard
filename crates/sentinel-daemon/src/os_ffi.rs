//! macOS-specific OS FFI for code-signing flag inspection.
//!
//! `csops` is an Apple-internal syscall (number 169 on macOS 14+) — undocumented
//! but stable. Verified from local SDK `/usr/include/sys/syscall.h` and the
//! XNU public source tree (`bsd/sys/codesign.h`).
//!
//! This module ONLY queries flags; it never modifies code-signing state. The
//! returned bits are used by the gap detector (D-34) to decide whether a
//! pending exec into a hardened-runtime binary will strip DYLD env vars.
//!
//! UNSUPPORTED-API CAVEAT: a future macOS may change CS_OPS_STATUS layout or
//! retire the syscall. The integration test `csops_on_self_returns_some_flags`
//! exercises the path on every CI run; if Apple changes layout the test fails
//! loudly rather than silently degrading.

/// macOS syscall number for csops. Verified from MacOSX15.4.sdk syscall.h.
///
/// Note: macOS `libc::syscall` takes `c_int` for the syscall number (unlike
/// Linux which takes `c_long`). 169 fits trivially in either width.
pub const SYS_CSOPS: libc::c_int = 169;

/// `cs_blobs.h` op codes / flag constants. Values verified from XNU
/// `bsd/sys/codesign.h` and the local 15.4 SDK kernel headers.
pub const CS_OPS_STATUS: u32 = 0;

pub const CS_HARD:       u32 = 0x0000_0100;  // don't load invalid pages
pub const CS_RESTRICT:   u32 = 0x0000_0800;  // tell dyld to treat restricted
pub const CS_REQUIRE_LV: u32 = 0x0000_2000;  // require library validation
pub const CS_RUNTIME:    u32 = 0x0001_0000;  // hardened runtime

/// Query code-signing flags for `pid` via the undocumented csops(2) syscall.
/// Returns the flags word or io::Error on syscall failure.
///
/// XNU signature (bsd/kern/kern_proc.c `__mac_get_proc_audit`):
///   int csops(pid_t pid, unsigned int ops, void *useraddr, size_t usersize)
pub fn csops_status(pid: libc::pid_t) -> Result<u32, std::io::Error> {
    let mut flags: u32 = 0;
    // SAFETY: libc::syscall is variadic; we pass the four csops args with
    // the widths Apple's XNU expects. `pid` and `ops` are `c_int`/`c_uint`
    // sized; the userspace pointer + size are pointer-width. The Apple
    // libc syscall stub marshals these to the kernel.
    let ret: libc::c_int = unsafe {
        libc::syscall(
            SYS_CSOPS,
            pid as libc::c_int,
            CS_OPS_STATUS as libc::c_uint,
            &mut flags as *mut u32 as *mut libc::c_void,
            std::mem::size_of::<u32>() as libc::size_t,
        )
    };
    if ret < 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(flags)
    }
}

/// True if the process at `pid` will strip DYLD_INSERT_LIBRARIES on exec.
/// Used by the D-34 Phase A pre-check. Conservative on syscall failure
/// (returns false → assumes not hardened so we don't false-positive a gap).
pub fn is_hardened_runtime(pid: libc::pid_t) -> bool {
    match csops_status(pid) {
        Ok(flags) => has_hardened_bits(flags),
        Err(_) => false,
    }
}

/// Pure helper — testable without a syscall. The set of bits any of which
/// indicate the binary will strip DYLD env vars on exec into a child.
pub fn has_hardened_bits(flags: u32) -> bool {
    (flags & CS_RESTRICT) != 0
        || (flags & CS_RUNTIME) != 0
        || (flags & CS_HARD) != 0
        || (flags & CS_REQUIRE_LV) != 0
}
