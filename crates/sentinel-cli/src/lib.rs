//! Sentinel CLI library — exposes spawn / locate / audit_token / ipc_client /
//! trust_policy for use by integration tests AND main.rs.

pub mod audit_token;
pub mod cli;
pub mod ipc_client;
pub mod locate;
pub mod spawn;
pub mod trust_policy;

#[derive(Debug, thiserror::Error)]
pub enum CliError {
    #[error("daemon not running or socket inaccessible: {0}")]
    DaemonUnreachable(String),
    #[error("dylib not found: {0}")]
    DylibNotFound(String),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("ipc: {0}")]
    Ipc(#[from] sentinel_ipc::IpcError),
    /// Generic CLI error with a free-form message — used for trust-policy
    /// (canonicalize / read / parse / TTY) and prepare_snapshot client paths.
    #[error("{0}")]
    Other(String),
}
