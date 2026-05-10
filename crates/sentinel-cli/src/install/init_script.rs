//! crates/sentinel-cli/src/install/init_script.rs
//!
//! Phase 3 plan 03-09 — single sourced init script (D-66).

use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

pub fn init_script_path() -> PathBuf {
    super::launchagent::home_dir().join(".config").join("sentinel").join("init.sh")
}

pub const INIT_SCRIPT_BODY: &str = include_str!("init_script_body.sh");

pub fn install(path: &Path) -> std::io::Result<String> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
        let _ = std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700));
    }
    let mut tf = tempfile::NamedTempFile::new_in(path.parent().unwrap())?;
    tf.write_all(INIT_SCRIPT_BODY.as_bytes())?;
    tf.as_file().sync_all()?;
    tf.persist(path).map_err(|e| std::io::Error::other(format!("persist: {e}")))?;
    let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
    let hash = sha256_hex(INIT_SCRIPT_BODY.as_bytes());
    Ok(hash)
}

pub fn strip(path: &Path) -> std::io::Result<()> {
    if path.exists() { std::fs::remove_file(path)?; }
    Ok(())
}

fn sha256_hex(b: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    format!("{:x}", Sha256::digest(b))
}
