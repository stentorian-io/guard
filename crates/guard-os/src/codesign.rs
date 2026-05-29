//! OS code-signing and hardened-runtime primitives.
//!
//! The current runtime implementation is macOS-only. Non-macOS targets expose
//! the same capability surface but return `Unsupported` for syscall-backed
//! queries.

use crate::OsError;
use guard_core::AuditToken;
#[cfg(target_os = "macos")]
use std::ffi::{c_char, c_void};

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
type SecCodeRef = *const c_void;
#[cfg(target_os = "macos")]
type CFDataRef = *const c_void;
#[cfg(target_os = "macos")]
type CFDictionaryRef = *const c_void;
#[cfg(target_os = "macos")]
type CFStringRef = *const c_void;
#[cfg(target_os = "macos")]
type CFAllocatorRef = *const c_void;

#[cfg(target_os = "macos")]
const ERR_SEC_SUCCESS: i32 = 0;
#[cfg(target_os = "macos")]
const KCF_STRING_ENCODING_UTF8: u32 = 0x0800_0100;

#[cfg(target_os = "macos")]
#[link(name = "Security", kind = "framework")]
unsafe extern "C" {
    fn SecCodeCopyGuestWithAttributes(
        host: SecCodeRef,
        attributes: CFDictionaryRef,
        flags: u32,
        guest: *mut SecCodeRef,
    ) -> i32;

    fn SecCodeCheckValidity(code: SecCodeRef, flags: u32, requirement: *const c_void) -> i32;
}

#[cfg(target_os = "macos")]
#[link(name = "CoreFoundation", kind = "framework")]
unsafe extern "C" {
    fn CFStringCreateWithCString(
        alloc: CFAllocatorRef,
        c_str: *const c_char,
        encoding: u32,
    ) -> CFStringRef;

    fn CFDataCreate(alloc: CFAllocatorRef, bytes: *const u8, length: isize) -> CFDataRef;

    fn CFDictionaryCreate(
        alloc: CFAllocatorRef,
        keys: *const *const c_void,
        values: *const *const c_void,
        num_values: isize,
        key_callbacks: *const c_void,
        value_callbacks: *const c_void,
    ) -> CFDictionaryRef;

    fn CFRelease(cf: *const c_void);

    static kCFTypeDictionaryKeyCallBacks: c_void;
    static kCFTypeDictionaryValueCallBacks: c_void;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CodesignVerdict {
    Valid,
    Invalid(i32),
    LookupFailed(i32),
    CfError(&'static str),
    Unsupported,
}

impl std::fmt::Display for CodesignVerdict {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Valid => write!(f, "valid"),
            Self::Invalid(s) => write!(f, "invalid (OSStatus {s})"),
            Self::LookupFailed(s) => write!(f, "lookup failed (OSStatus {s})"),
            Self::CfError(msg) => write!(f, "CF error: {msg}"),
            Self::Unsupported => write!(f, "unsupported"),
        }
    }
}

#[cfg(target_os = "macos")]
struct CfGuard(*const c_void);

#[cfg(target_os = "macos")]
impl Drop for CfGuard {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe { CFRelease(self.0) };
        }
    }
}

#[cfg(target_os = "macos")]
mod imp {
    use super::{CS_OPS_STATUS, CSOPS_STATUS, OsError, SYS_CSOPS};

    pub fn csops_status(pid: libc::pid_t) -> Result<u32, OsError> {
        let mut flags: u32 = 0;
        let ret: libc::c_int = unsafe {
            libc::syscall(
                SYS_CSOPS,
                pid as libc::c_int,
                CS_OPS_STATUS as libc::c_uint,
                (&raw mut flags).cast::<libc::c_void>(),
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
    use super::{CSOPS_STATUS, OsError};

    pub fn csops_status(_pid: libc::pid_t) -> Result<u32, OsError> {
        Err(OsError::unsupported(CSOPS_STATUS))
    }
}

/// Query code-signing flags for `pid` via the OS code-signing status API.
///
/// # Errors
///
/// Returns an OS error when the platform call fails or the capability is
/// unsupported.
pub fn csops_status(pid: libc::pid_t) -> Result<u32, OsError> {
    imp::csops_status(pid)
}

/// True if the process at `pid` will strip `DYLD_INSERT_LIBRARIES` on exec.
/// Conservative on syscall failure or unsupported targets.
#[must_use]
pub fn is_hardened_runtime(pid: libc::pid_t) -> bool {
    match csops_status(pid) {
        Ok(flags) => has_hardened_bits(flags),
        Err(_) => false,
    }
}

/// Pure helper: the set of bits, any of which indicate the binary will strip
/// DYLD env vars on exec into a child.
#[must_use]
pub fn has_hardened_bits(flags: u32) -> bool {
    (flags & CS_RESTRICT) != 0
        || (flags & CS_RUNTIME) != 0
        || (flags & CS_HARD) != 0
        || (flags & CS_REQUIRE_LV) != 0
}

/// Verify the code signature of the process identified by `token`.
///
/// Returns `CodesignVerdict::Valid` if the signature checks out. This function
/// does not make policy decisions.
#[cfg(target_os = "macos")]
#[must_use]
pub fn verify_peer_signature(token: &AuditToken) -> CodesignVerdict {
    unsafe {
        let key = CFStringCreateWithCString(
            std::ptr::null(),
            c"audit".as_ptr(),
            KCF_STRING_ENCODING_UTF8,
        );
        if key.is_null() {
            return CodesignVerdict::CfError("CFStringCreateWithCString failed");
        }
        let _key_guard = CfGuard(key);

        let Ok(token_len) = isize::try_from(std::mem::size_of_val(&token.val)) else {
            return CodesignVerdict::CfError("audit token length does not fit CFIndex");
        };

        let token_data = CFDataCreate(std::ptr::null(), token.val.as_ptr().cast::<u8>(), token_len);
        if token_data.is_null() {
            return CodesignVerdict::CfError("CFDataCreate failed");
        }
        let _data_guard = CfGuard(token_data);

        let keys = [key];
        let values = [token_data];
        let dict = CFDictionaryCreate(
            std::ptr::null(),
            keys.as_ptr(),
            values.as_ptr(),
            1,
            &raw const kCFTypeDictionaryKeyCallBacks,
            &raw const kCFTypeDictionaryValueCallBacks,
        );
        if dict.is_null() {
            return CodesignVerdict::CfError("CFDictionaryCreate failed");
        }
        let _dict_guard = CfGuard(dict);

        let mut code_ref: SecCodeRef = std::ptr::null();
        let status = SecCodeCopyGuestWithAttributes(std::ptr::null(), dict, 0, &raw mut code_ref);
        if status != ERR_SEC_SUCCESS || code_ref.is_null() {
            return CodesignVerdict::LookupFailed(status);
        }
        let _code_guard = CfGuard(code_ref);

        let check = SecCodeCheckValidity(code_ref, 0, std::ptr::null());
        if check == ERR_SEC_SUCCESS {
            CodesignVerdict::Valid
        } else {
            CodesignVerdict::Invalid(check)
        }
    }
}

#[cfg(not(target_os = "macos"))]
#[must_use]
pub fn verify_peer_signature(_token: &AuditToken) -> CodesignVerdict {
    CodesignVerdict::Unsupported
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

    #[cfg(target_os = "macos")]
    #[test]
    fn verify_own_process_returns_known_verdict() {
        let pid = u32::try_from(unsafe { libc::getpid() }).expect("self pid is positive");
        let token = AuditToken::synthetic([0, 0, 0, 0, 0, pid, 0, 0]);
        let verdict = verify_peer_signature(&token);
        match verdict {
            CodesignVerdict::Valid
            | CodesignVerdict::Invalid(_)
            | CodesignVerdict::LookupFailed(_) => {}
            CodesignVerdict::CfError(msg) => {
                panic!("unexpected CF error on own pid: {msg}");
            }
            CodesignVerdict::Unsupported => panic!("macOS codesign should be supported"),
        }
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn verify_dead_process_returns_lookup_failed_or_invalid() {
        let token = AuditToken::synthetic([0, 0, 0, 0, 0, 99999, 0, 0]);
        let verdict = verify_peer_signature(&token);
        assert!(
            matches!(
                verdict,
                CodesignVerdict::LookupFailed(_) | CodesignVerdict::Invalid(_)
            ),
            "expected LookupFailed or Invalid for dead pid, got {verdict}"
        );
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
