//! sentineld library — exposes the daemon internals to integration tests.
pub mod baseline_staging;
pub mod codesign;
pub mod hmac_key;
pub mod curated;
pub mod daemon_state;
pub mod log_writer;
pub mod prompt;
pub mod env_capture;
pub mod gap_detector;
pub mod install_artifacts;
pub mod handlers;
pub mod state_dir;
pub mod snapshot;
pub mod snapshot_gc;
pub mod manifest;
pub mod ipc_dispatch;
pub mod ipc_server;
pub mod os_ffi;
pub mod peer_auth;
pub mod tracked;
pub mod persistence_watcher;
pub mod rule_store;

// Convenience re-exports for integration tests.
pub use ipc_server::DaemonState;
/// Re-export Verdict under `sentinel_daemon::policy::Verdict` for test ergonomics.
pub mod policy {
    pub use sentinel_core::Verdict;
}
