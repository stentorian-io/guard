//! HMAC key management for snapshot integrity (M004-S02).
//!
//! The key is a 32-byte random value stored at `state_dir/hmac.key` with
//! mode 0600. Generated once at install time; read by both the daemon
//! (signing) and the hook dylib (verification).

use std::fs::OpenOptions;
use std::io::{Read, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

pub const KEY_FILENAME: &str = "hmac.key";
pub const KEY_LEN: usize = 32;

pub fn key_path(state_dir: &Path) -> PathBuf {
    state_dir.join(KEY_FILENAME)
}

/// Generate a new 32-byte HMAC key and write it to `state_dir/hmac.key`
/// with mode 0600. Returns the key bytes. Overwrites any existing key
/// (idempotent for reinstall).
pub fn generate_and_store(state_dir: &Path) -> std::io::Result<[u8; KEY_LEN]> {
    let mut key = [0u8; KEY_LEN];
    getrandom::getrandom(&mut key).map_err(|e| std::io::Error::other(format!("getrandom: {e}")))?;

    let path = key_path(state_dir);
    let mut f = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(&path)?;
    f.write_all(&key)?;
    f.sync_all()?;
    Ok(key)
}

/// Load the HMAC key from disk. Returns None if the file doesn't exist
/// or is the wrong length.
pub fn load(state_dir: &Path) -> Option<[u8; KEY_LEN]> {
    let path = key_path(state_dir);
    let mut f = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&path)
        .ok()?;
    let mut buf = [0u8; KEY_LEN];
    let n = f.read(&mut buf).ok()?;
    if n != KEY_LEN {
        return None;
    }
    // Ensure no trailing bytes (file must be exactly KEY_LEN)
    let mut extra = [0u8; 1];
    if f.read(&mut extra).ok() != Some(0) {
        return None;
    }
    Some(buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_and_load_roundtrip() {
        let tmp = tempfile::tempdir().unwrap();
        let key = generate_and_store(tmp.path()).unwrap();
        assert_ne!(key, [0u8; KEY_LEN]);
        let loaded = load(tmp.path()).unwrap();
        assert_eq!(key, loaded);
    }

    #[test]
    fn load_returns_none_when_missing() {
        let tmp = tempfile::tempdir().unwrap();
        assert!(load(tmp.path()).is_none());
    }

    #[test]
    fn load_returns_none_for_wrong_length() {
        let tmp = tempfile::tempdir().unwrap();
        let path = key_path(tmp.path());
        std::fs::write(&path, &[0u8; 16]).unwrap();
        assert!(load(tmp.path()).is_none());
    }

    #[test]
    fn file_permissions_are_0600() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = tempfile::tempdir().unwrap();
        generate_and_store(tmp.path()).unwrap();
        let path = key_path(tmp.path());
        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }
}
