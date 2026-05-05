//! Filesystem layout for the Phase 1 daemon.
//!
//! All paths derive from `default_state_dir()`. The dylib (plan 06) MUST
//! validate that the env-var-supplied manifest path canonicalizes to live
//! under this directory — see threat model T-01-05-02.

use std::path::{Path, PathBuf};

pub fn default_state_dir() -> PathBuf {
    let home = std::env::var_os("HOME").expect("HOME environment variable must be set");
    PathBuf::from(home).join("Library/Application Support/Sentinel")
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
    state_dir.join("sentineld.sock")
}

pub fn ready_path(state_dir: &Path) -> PathBuf {
    state_dir.join("daemon.ready")
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
