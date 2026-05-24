//! OS code-signing and hardened-runtime primitives.
//!
//! The current runtime implementation is macOS-only. Non-macOS targets expose
//! the same capability surface but return `Unsupported` for syscall-backed
//! queries.

use crate::OsError;

/// macOS syscall number for csops. Verified from MacOSX15.4.sdk syscall.h.
pub const SYS_CSOPS: libc::c_int = 169;

/// `cs_blobs.h` op codes / flag constants. Values verified from XNU
/// `bsd/sys/codesign.h` and the local 15.4 SDK kernel headers.
pub const CS_OPS_STATUS: u32 = 0;

pub const CS_HARD: u32 = 0x0000_0100; // don't load invalid pages
pub const CS_RESTRICT: u32 = 0x0000_0800; // tell dyld to treat restricted
pub const CS_REQUIRE_LV: u32 = 0x0000_2000; // require library validation
pub const CS_RUNTIME: u32 = 0x0001_0000; // hardened runtime

const CSOPS_STATUS: &str = "csops status";

#[cfg(target_os = "macos")]
mod imp {
    use super::*;

    pub fn csops_status(pid: libc::pid_t) -> Result<u32, OsError> {
        let mut flags: u32 = 0;
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
            Err(OsError::io(CSOPS_STATUS, std::io::Error::last_os_error()))
        } else {
            Ok(flags)
        }
    }
}

#[cfg(not(target_os = "macos"))]
mod imp {
    use super::*;

    pub fn csops_status(_pid: libc::pid_t) -> Result<u32, OsError> {
        Err(OsError::unsupported(CSOPS_STATUS))
    }
}

/// Query code-signing flags for `pid` via the OS code-signing status API.
pub fn csops_status(pid: libc::pid_t) -> Result<u32, OsError> {
    imp::csops_status(pid)
}

/// True if the process at `pid` will strip DYLD_INSERT_LIBRARIES on exec.
/// Conservative on syscall failure or unsupported targets.
pub fn is_hardened_runtime(pid: libc::pid_t) -> bool {
    match csops_status(pid) {
        Ok(flags) => has_hardened_bits(flags),
        Err(_) => false,
    }
}

/// Pure helper: the set of bits, any of which indicate the binary will strip
/// DYLD env vars on exec into a child.
pub fn has_hardened_bits(flags: u32) -> bool {
    (flags & CS_RESTRICT) != 0
        || (flags & CS_RUNTIME) != 0
        || (flags & CS_HARD) != 0
        || (flags & CS_REQUIRE_LV) != 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn constants_have_expected_values() {
        assert_eq!(SYS_CSOPS, 169);
        assert_eq!(CS_OPS_STATUS, 0);
        assert_eq!(CS_HARD, 0x100);
        assert_eq!(CS_RESTRICT, 0x800);
        assert_eq!(CS_REQUIRE_LV, 0x2000);
        assert_eq!(CS_RUNTIME, 0x10000);
    }

    #[test]
    fn has_hardened_bits_detects_each_flag_alone() {
        assert!(has_hardened_bits(CS_RESTRICT));
        assert!(has_hardened_bits(CS_RUNTIME));
        assert!(has_hardened_bits(CS_HARD));
        assert!(has_hardened_bits(CS_REQUIRE_LV));
        assert!(!has_hardened_bits(0));
        assert!(!has_hardened_bits(0x4000));
    }

    #[test]
    fn has_hardened_bits_detects_combinations() {
        assert!(has_hardened_bits(CS_RESTRICT | CS_RUNTIME));
        assert!(has_hardened_bits(CS_HARD | CS_REQUIRE_LV | 0x4000));
    }

    #[cfg(not(target_os = "macos"))]
    #[test]
    fn csops_status_is_explicitly_unsupported() {
        let err = csops_status(1).expect_err("non-macOS csops");
        assert!(matches!(
            err,
            OsError::Unsupported {
                capability: CSOPS_STATUS,
                ..
            }
        ));
        assert!(!is_hardened_runtime(1));
    }
}
