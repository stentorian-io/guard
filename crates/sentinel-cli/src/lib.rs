//! Sentinel CLI library — exposes spawn / locate / audit_token / ipc_client /
//! for use by integration tests AND main.rs.

pub mod audit_token;
pub mod biometric;
pub mod cli;
pub mod denial_log;
pub mod ensure_daemon;
pub mod install;
pub mod persistence_log;
pub mod ipc_client;
pub mod locate;
pub mod logs;
pub mod prompt_channel;
pub mod prompt_render;
pub mod run_orchestrator;
pub mod sigint_handler;
pub mod spawn;
pub mod status;
pub mod tty;

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
    /// Generic CLI error with a free-form message.
    #[error("{0}")]
    Other(String),
}
