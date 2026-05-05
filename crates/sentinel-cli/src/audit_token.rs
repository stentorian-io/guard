//! audit_token_for_pid FFI. (RED stub)
use sentinel_core::AuditToken;

pub fn audit_token_for_pid(_pid: libc::pid_t) -> std::io::Result<AuditToken> {
    Err(std::io::Error::other("audit_token_for_pid not yet implemented"))
}
