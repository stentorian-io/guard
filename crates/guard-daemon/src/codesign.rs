//! Codesign peer verification policy.
//!
//! The OS-specific Security.framework lookup lives in `guard-os`; this module
//! applies daemon policy and logging to the returned verdict.

use guard_core::AuditToken;
use guard_os::codesign::{CodesignVerdict, verify_peer_signature};
use tracing::{debug, warn};

/// Check peer codesign and apply policy. Returns `true` if the peer should
/// be accepted, `false` if it should be rejected.
///
/// Policy: strict — Valid is accepted, Invalid and `CfError` are rejected.
/// `LookupFailed` is accepted (peer may have exited between connect and check).
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
        CodesignVerdict::Unsupported => {
            warn!(
                peer_pid = pid,
                "codesign: unsupported platform — rejecting peer"
            );
            false
        }
    }
}

#[cfg(all(test, target_os = "macos"))]
mod tests {
    use super::*;

    #[test]
    fn should_accept_peer_accepts_own_process() {
        let pid = u32::try_from(unsafe { libc::getpid() }).expect("pid fits audit token field");
        let token = AuditToken::synthetic([0, 0, 0, 0, 0, pid, 0, 0]);
        assert!(should_accept_peer(&token));
    }
}
