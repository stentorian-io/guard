//! sentineld library — exposes the daemon internals to integration tests.
pub mod curated;
pub mod gap_detector;
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
pub mod dev_install;
pub mod rule_store;
pub mod policy_file;
