//! Snapshot publication: const allowlist → CBOR file with O_EXCL + fsync + rename.
//! Pattern 4 from .planning/phases/01-foundations-hook-hello-world/01-RESEARCH.md.
//!
//! Phase 2 (D-29) adds `publish_run` for per-run snapshot lifecycle: writes to
//! `${state_dir}/runs/{run-uuid}.cbor` plus a matching `{run-uuid}.manifest`
//! atomically (tmp + fsync + rename). The Phase 1 `publish` function remains for
//! the daemon-startup snapshot at the legacy path scheme.

use crate::state_dir::{
    ensure_runs_dir, run_manifest_path, run_manifest_tmp_path, run_snapshot_path,
    run_snapshot_tmp_path, snapshot_path, snapshot_tmp_path,
};
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

/// Per-run snapshot publish (D-29). Writes to runs/{uuid}.cbor + runs/{uuid}.manifest
/// atomically (tmp + fsync + rename). Distinct from Phase 1's `publish` which writes
/// the daemon-startup snapshot at a different path scheme.
///
/// The manifest format matches Phase 1's: line 1 = absolute snapshot path,
/// line 2 = "digest=<hex>\n". The dylib's existing snapshot loader consumes
/// it unchanged.
pub fn publish_run(
    state_dir: &Path,
    snap: &Snapshot,
    run_uuid: &str,
) -> std::io::Result<PublishedSnapshot> {
    ensure_runs_dir(state_dir)?;
    let bytes = snap
        .encode()
        .map_err(|e| std::io::Error::other(format!("encode: {e}")))?;

    // Snapshot file: tmp + fsync + rename.
    let tmp = run_snapshot_tmp_path(state_dir, run_uuid);
    let final_path = run_snapshot_path(state_dir, run_uuid);
    // Best-effort cleanup of any leftover tmp from an interrupted prior run.
    let _ = std::fs::remove_file(&tmp);
    {
        let mut f = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&tmp)?;
        f.write_all(&bytes)?;
        f.sync_all()?;
    }
    std::fs::rename(&tmp, &final_path)?;

    let digest = Sha256::digest(&bytes);
    let digest_hex = hex_lower(&digest);

    // Manifest file: tmp + fsync + rename. Same shape as Phase 1 manifest::write.
    let manifest_tmp = run_manifest_tmp_path(state_dir, run_uuid);
    let manifest_final = run_manifest_path(state_dir, run_uuid);
    let _ = std::fs::remove_file(&manifest_tmp);
    {
        let mut f = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&manifest_tmp)?;
        let body = format!("{}\ndigest={}\n", final_path.display(), digest_hex);
        f.write_all(body.as_bytes())?;
        f.sync_all()?;
    }
    std::fs::rename(&manifest_tmp, &manifest_final)?;

    Ok(PublishedSnapshot {
        path: final_path,
        digest_hex,
    })
}

/// GC a per-run snapshot+manifest pair. Best-effort: missing files are not errors.
/// Plan 02-07 calls this on tracked-root exit.
pub fn gc_run(state_dir: &Path, run_uuid: &str) {
    let _ = std::fs::remove_file(run_snapshot_path(state_dir, run_uuid));
    let _ = std::fs::remove_file(run_manifest_path(state_dir, run_uuid));
}
