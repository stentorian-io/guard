//! Snapshot publication: const allowlist → CBOR file with O_EXCL + fsync + rename.
//! Pattern 4 from .planning/phases/01-foundations-hook-hello-world/01-RESEARCH.md.

use crate::state_dir::{snapshot_path, snapshot_tmp_path};
use sentinel_core::Snapshot;
use sha2::{Digest, Sha256};
use std::fs::OpenOptions;
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

pub struct PublishedSnapshot {
    pub path: PathBuf,
    pub digest_hex: String,
}

/// Write `snap` to `state_dir` with mode 0600 atomically. Returns the absolute
/// path to the new snapshot file plus the SHA-256 digest of its bytes.
///
/// Order: write tmp (O_EXCL | O_CREAT, mode 0600) → fsync → rename to final.
pub fn publish(state_dir: &Path, snap: &Snapshot, nonce: u64) -> std::io::Result<PublishedSnapshot> {
    let bytes = snap.encode().map_err(|e| std::io::Error::other(format!("encode: {e}")))?;
    let tmp = snapshot_tmp_path(state_dir, nonce);
    let final_path = snapshot_path(state_dir, nonce);

    {
        let mut f = OpenOptions::new()
            .write(true)
            .create_new(true) // O_EXCL | O_CREAT
            .mode(0o600)
            .open(&tmp)?;
        f.write_all(&bytes)?;
        f.sync_all()?;
    }
    std::fs::rename(&tmp, &final_path)?;
    let digest = Sha256::digest(&bytes);
    Ok(PublishedSnapshot {
        path: final_path,
        digest_hex: hex_lower(&digest),
    })
}

fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 0xf) as usize] as char);
    }
    s
}
