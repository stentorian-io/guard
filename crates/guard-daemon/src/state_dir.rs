//! Filesystem layout for the daemon.
//!
//! All path builders and constants are defined in `guard_core::paths`.
//! This module re-exports everything for backward compatibility within
//! the daemon crate.

pub use guard_core::paths::{
    db_path, default_state_dir, ensure_runs_dir, ensure_state_dir, is_system_install,
    manifest_path, manifest_tmp_path, ready_path, run_manifest_path, run_manifest_tmp_path,
    run_snapshot_path, run_snapshot_tmp_path, runs_dir, snapshot_path, snapshot_tmp_path,
    socket_path,
};
