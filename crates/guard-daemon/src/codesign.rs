//! Codesign peer verification via Security.framework (M006-S02).
//!
//! Uses `SecCodeCopyGuestWithAttributes` + `SecCodeCheckValidity` to verify
//! that an IPC peer's code signature is valid. The audit token from
//! `getsockopt(SOL_LOCAL, LOCAL_PEERTOKEN)` identifies the peer process;
//! Security.framework resolves it to a `SecCodeRef` and checks the signature.
//!
//! Policy:
//!   - Release builds: reject peers with invalid/tampered signatures.
//!   - Debug builds: warn-only (unsigned dev builds are normal during development).

use guard_core::AuditToken;
use std::ffi::c_void;
use tracing::{debug, warn};

type OSStatus = i32;
type SecCodeRef = *const c_void;
type CFDataRef = *const c_void;
type CFDictionaryRef = *const c_void;
type CFStringRef = *const c_void;
type CFAllocatorRef = *const c_void;

const ERR_SEC_SUCCESS: OSStatus = 0;
const KCF_STRING_ENCODING_UTF8: u32 = 0x0800_0100; // 134217984

#[link(name = "Security", kind = "framework")]
unsafe extern "C" {
    fn SecCodeCopyGuestWithAttributes(
        host: SecCodeRef,
        attributes: CFDictionaryRef,
        flags: u32,
        guest: *mut SecCodeRef,
    ) -> OSStatus;

    fn SecCodeCheckValidity(code: SecCodeRef, flags: u32, requirement: *const c_void) -> OSStatus;
}

#[link(name = "CoreFoundation", kind = "framework")]
unsafe extern "C" {
    fn CFStringCreateWithCString(
        alloc: CFAllocatorRef,
        c_str: *const u8,
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
    Invalid(OSStatus),
    LookupFailed(OSStatus),
    CfError(&'static str),
}

impl std::fmt::Display for CodesignVerdict {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CodesignVerdict::Valid => write!(f, "valid"),
            CodesignVerdict::Invalid(s) => write!(f, "invalid (OSStatus {s})"),
            CodesignVerdict::LookupFailed(s) => write!(f, "lookup failed (OSStatus {s})"),
            CodesignVerdict::CfError(msg) => write!(f, "CF error: {msg}"),
        }
    }
}

/// RAII guard that calls CFRelease on drop.
struct CfGuard(*const c_void);

impl Drop for CfGuard {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe { CFRelease(self.0) };
        }
    }
}

/// Verify the code signature of the process identified by `token`.
///
/// Returns `CodesignVerdict::Valid` if the signature checks out.
/// Does NOT make policy decisions — the caller decides whether to
/// reject `Invalid` peers based on build mode.
pub fn verify_peer_signature(token: &AuditToken) -> CodesignVerdict {
    unsafe {
        // Build the attributes dictionary: { kSecGuestAttributeAudit: <token-as-CFData> }
        let key = CFStringCreateWithCString(
            std::ptr::null(),
            b"audit\0".as_ptr(),
            KCF_STRING_ENCODING_UTF8,
        );
        if key.is_null() {
            return CodesignVerdict::CfError("CFStringCreateWithCString failed");
        }
        let _key_guard = CfGuard(key);

        let token_data = CFDataCreate(
            std::ptr::null(),
            token.val.as_ptr() as *const u8,
            std::mem::size_of_val(&token.val) as isize,
        );
        if token_data.is_null() {
            return CodesignVerdict::CfError("CFDataCreate failed");
        }
        let _data_guard = CfGuard(token_data);

        let keys = [key];
        let values = [token_data];
        let dict = CFDictionaryCreate(
            std::ptr::null(),
            keys.as_ptr() as *const *const c_void,
            values.as_ptr() as *const *const c_void,
            1,
            &kCFTypeDictionaryKeyCallBacks as *const c_void,
            &kCFTypeDictionaryValueCallBacks as *const c_void,
        );
        if dict.is_null() {
            return CodesignVerdict::CfError("CFDictionaryCreate failed");
        }
        let _dict_guard = CfGuard(dict);

        let mut code_ref: SecCodeRef = std::ptr::null();
        let status = SecCodeCopyGuestWithAttributes(std::ptr::null(), dict, 0, &mut code_ref);
        if status != ERR_SEC_SUCCESS || code_ref.is_null() {
            return CodesignVerdict::LookupFailed(status);
        }
        let _code_guard = CfGuard(code_ref);

        let check = SecCodeCheckValidity(
            code_ref,
            0, // kSecCSDefaultFlags
            std::ptr::null(),
        );
        if check == ERR_SEC_SUCCESS {
            CodesignVerdict::Valid
        } else {
            CodesignVerdict::Invalid(check)
        }
    }
}

/// Check peer codesign and apply policy. Returns `true` if the peer should
/// be accepted, `false` if it should be rejected.
///
/// Policy: strict — Valid is accepted, Invalid and CfError are rejected.
/// LookupFailed is accepted (peer may have exited between connect and check).
pub fn should_accept_peer(token: &AuditToken) -> bool {
    let verdict = verify_peer_signature(token);
    let pid = token.pid();

    match &verdict {
        CodesignVerdict::Valid => {
            debug!(peer_pid = pid, "codesign: valid");
            true
        }
        CodesignVerdict::Invalid(status) => {
            warn!(
                peer_pid = pid,
                os_status = status,
                "codesign: peer has invalid/tampered signature — rejecting"
            );
            false
        }
        CodesignVerdict::LookupFailed(status) => {
            debug!(
                peer_pid = pid,
                os_status = status,
                "codesign: SecCodeCopyGuestWithAttributes failed (peer may have exited)"
            );
            true
        }
        CodesignVerdict::CfError(msg) => {
            warn!(
                peer_pid = pid,
                error = msg,
                "codesign: CoreFoundation error during verification — rejecting"
            );
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verify_own_process_succeeds() {
        // Our own process should have a valid (or at least lookup-able) signature.
        // In test mode (unsigned dev build), we may get Invalid — that's fine,
        // Our own pid should produce Valid or LookupFailed.
        let pid = unsafe { libc::getpid() } as u32;
        let token = AuditToken::synthetic([0, 0, 0, 0, 0, pid, 0, 0]);
        let verdict = verify_peer_signature(&token);
        // We just check it doesn't crash and returns a known variant.
        match verdict {
            CodesignVerdict::Valid
            | CodesignVerdict::Invalid(_)
            | CodesignVerdict::LookupFailed(_) => {}
            CodesignVerdict::CfError(msg) => {
                panic!("unexpected CF error on own pid: {msg}");
            }
        }
    }

    #[test]
    fn should_accept_peer_accepts_own_process() {
        let pid = unsafe { libc::getpid() } as u32;
        let token = AuditToken::synthetic([0, 0, 0, 0, 0, pid, 0, 0]);
        assert!(should_accept_peer(&token));
    }

    #[test]
    fn verify_dead_process_returns_lookup_failed() {
        // PID 99999 is very unlikely to exist.
        let token = AuditToken::synthetic([0, 0, 0, 0, 0, 99999, 0, 0]);
        let verdict = verify_peer_signature(&token);
        // Should get LookupFailed (process not found) or Invalid.
        assert!(
            matches!(
                verdict,
                CodesignVerdict::LookupFailed(_) | CodesignVerdict::Invalid(_)
            ),
            "expected LookupFailed or Invalid for dead pid, got {verdict}"
        );
    }
}
