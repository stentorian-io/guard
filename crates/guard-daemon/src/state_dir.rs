//! Filesystem layout for the v0.1 daemon.
//!
//! All paths derive from `default_state_dir()`. The dylib (plan 06) MUST
//! validate that the env-var-supplied manifest path canonicalizes to live
//! under this directory — see threat model T-01-05-02.

use std::path::{Path, PathBuf};

pub fn default_state_dir() -> PathBuf {
    if let Some(dir) = std::env::var_os("STT_GUARD_STATE_DIR") {
        return PathBuf::from(dir);
    }
    let home = std::env::var_os("HOME").expect("HOME environment variable must be set");
    PathBuf::from(home).join("Library/Application Support/Stentorian Guard")
}

pub fn snapshot_path(state_dir: &Path, nonce: u64) -> PathBuf {
    state_dir.join(format!("snapshot-{nonce:016x}.cbor"))
}

pub fn snapshot_tmp_path(state_dir: &Path, nonce: u64) -> PathBuf {
    state_dir.join(format!(".snapshot-{nonce:016x}.cbor.tmp"))
}

pub fn manifest_path(state_dir: &Path) -> PathBuf {
    state_dir.join("snapshot.manifest")
}

pub fn manifest_tmp_path(state_dir: &Path) -> PathBuf {
    state_dir.join(".snapshot.manifest.tmp")
}

pub fn socket_path(state_dir: &Path) -> PathBuf {
    state_dir.join("stt-guard-daemon.sock")
}

pub fn ready_path(state_dir: &Path) -> PathBuf {
    state_dir.join("daemon.ready")
}

pub fn db_path(state_dir: &Path) -> PathBuf {
    state_dir.join("stt-guard.db")
}

/// Create state_dir with mode 0700 if missing. Idempotent.
pub fn ensure_state_dir(state_dir: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::DirBuilderExt;
    if state_dir.exists() {
        return Ok(());
    }
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(state_dir)
}

// --- Per-run snapshot path helpers (v0.2) -------------------------------------

pub fn runs_dir(state_dir: &Path) -> PathBuf {
    state_dir.join("runs")
}

pub fn run_snapshot_path(state_dir: &Path, run_uuid: &str) -> PathBuf {
    runs_dir(state_dir).join(format!("{run_uuid}.cbor"))
}

pub fn run_snapshot_tmp_path(state_dir: &Path, run_uuid: &str) -> PathBuf {
    runs_dir(state_dir).join(format!(".{run_uuid}.cbor.tmp"))
}

pub fn run_manifest_path(state_dir: &Path, run_uuid: &str) -> PathBuf {
    runs_dir(state_dir).join(format!("{run_uuid}.manifest"))
}

pub fn run_manifest_tmp_path(state_dir: &Path, run_uuid: &str) -> PathBuf {
    runs_dir(state_dir).join(format!(".{run_uuid}.manifest.tmp"))
}

/// Create runs/ subdirectory with mode 0700 if missing. Idempotent.
pub fn ensure_runs_dir(state_dir: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::DirBuilderExt;
    let dir = runs_dir(state_dir);
    if dir.exists() {
        return Ok(());
    }
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(dir)
}

// --- Per-feed cache directory helpers (v0.4) ----------------------------------
