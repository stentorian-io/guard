//! stt-guard-daemon library — exposes the daemon internals to integration tests.
pub mod baseline_staging;
pub mod codesign;
pub mod curated;
pub mod daemon_state;
pub mod env_capture;
pub mod gap_detector;
pub mod handlers;
pub mod install_artifacts;
pub mod ipc_dispatch;
pub mod ipc_server;
pub mod log_writer;
pub mod management_auth;
pub mod manifest;
pub mod peer_auth;
pub mod persistence_watcher;
pub mod prompt;
pub mod rule_store;
pub mod snapshot;
pub mod snapshot_gc;
pub mod state_dir;
pub mod tracked;

// Convenience re-exports for integration tests.
pub use ipc_server::DaemonState;
/// Re-export Verdict under `guard_daemon::policy::Verdict` for test ergonomics.
pub mod policy {
    pub use guard_core::Verdict;
}
