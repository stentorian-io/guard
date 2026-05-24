//! Compatibility wrapper for process audit-token derivation.

use guard_core::AuditToken;

pub fn audit_token_for_pid(pid: libc::pid_t) -> std::io::Result<AuditToken> {
    guard_os::audit_token::audit_token_for_pid(pid).map_err(std::io::Error::other)
}
