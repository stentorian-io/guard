//! Path helpers for Sentinel's log and home directories.

use std::path::PathBuf;

pub fn home_dir() -> PathBuf {
    std::env::var_os("HOME").map(PathBuf::from).unwrap_or_else(|| PathBuf::from("/tmp"))
}

pub fn logs_dir() -> PathBuf {
    home_dir().join("Library").join("Logs").join("Sentinel")
}
