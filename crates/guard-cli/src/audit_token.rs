//! Compatibility wrapper for process audit-token derivation.

use guard_core::AuditToken;

/// Derive an audit token for a process id.
///
/// # Errors
///
/// Returns an error when the OS audit-token lookup fails.
pub fn audit_token_for_pid(pid: libc::pid_t) -> std::io::Result<AuditToken> {
    guard_os::audit_token::audit_token_for_pid(pid).map_err(std::io::Error::other)
}
