//! Path helpers for Stentorian Guard's log and home directories.

use std::path::PathBuf;

/// Return the current user's home directory.
///
/// # Panics
///
/// Panics when `HOME` is not present in the process environment.
pub fn home_dir() -> PathBuf {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .expect("HOME environment variable must be set")
}

#[must_use]
pub fn logs_dir() -> PathBuf {
    let state_dir = guard_core::paths::default_state_dir();
    guard_core::paths::log_dir_for_state(&state_dir)
}
