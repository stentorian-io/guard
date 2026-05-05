//! IPC client. (RED stub)
use sentinel_core::AuditToken;
use std::path::Path;

pub fn register_root_with_daemon(_sock: &Path, _token: AuditToken) -> Result<(), crate::CliError> {
    Err(crate::CliError::DaemonUnreachable("register_root not yet implemented".into()))
}

pub fn probe_daemon_alive(_sock: &Path) -> Result<(), crate::CliError> {
    Err(crate::CliError::DaemonUnreachable("probe_daemon_alive not yet implemented".into()))
}
