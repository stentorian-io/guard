//! Snapshot publication: const allowlist → CBOR file with O_EXCL + fsync + rename.
//! Snapshot publication: const allowlist -> CBOR file with O_EXCL + fsync + rename.
//!
//! v0.2 adds `publish_run` for per-run snapshot lifecycle: writes read-only
//! signed policy artifacts to `${state_dir}/runs/{run-uuid}.cbor` plus a
//! matching `{run-uuid}.manifest` atomically (tmp + fsync + rename). The v0.1
//! `publish` function remains for the daemon-startup snapshot at the legacy
//! path scheme.

use crate::state_dir::{
    ensure_runs_dir, run_manifest_path, run_manifest_tmp_path, run_snapshot_path,
    run_snapshot_tmp_path, snapshot_path, snapshot_tmp_path,
};
use guard_core::Snapshot;
use sha2::{Digest, Sha256};
use std::fs::OpenOptions;
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

const PER_RUN_ARTIFACT_MODE: u32 = 0o644;

pub struct PublishedSnapshot {
    pub path: PathBuf,
    pub digest_hex: String,
}

/// Write `snap` to `state_dir` with mode 0600 atomically. Returns the absolute
/// path to the new snapshot file plus the SHA-256 digest of its bytes.
///
/// Order: write tmp (O_EXCL | O_CREAT, mode 0600) → fsync → rename to final.
pub fn publish(
    state_dir: &Path,
    snap: &Snapshot,
    nonce: u64,
) -> std::io::Result<PublishedSnapshot> {
    let bytes = snap
        .encode()
        .map_err(|e| std::io::Error::other(format!("encode: {e}")))?;
    let tmp = snapshot_tmp_path(state_dir, nonce);
    let final_path = snapshot_path(state_dir, nonce);

    {
        let mut f = OpenOptions::new()
            .write(true)
            .create_new(true) // O_EXCL | O_CREAT
            .mode(0o600)
            .open(&tmp)?;
        f.write_all(bytes.as_slice())?;
        f.sync_all()?;
    }
    std::fs::rename(&tmp, &final_path)?;
    let digest = Sha256::digest(bytes.as_slice());
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

/// Per-run snapshot publish. Writes to runs/{uuid}.cbor + runs/{uuid}.manifest
/// atomically (tmp + fsync + rename). Distinct from v0.1's `publish` which writes
/// the daemon-startup snapshot at a different path scheme.
///
/// Manifest format:
///   line 1 = absolute snapshot path
///   line 2 = "digest=<hex>"
///   remaining lines = hardware-backed snapshot signature metadata
pub fn publish_run(
    state_dir: &Path,
    snap: &Snapshot,
    run_uuid: &str,
) -> std::io::Result<PublishedSnapshot> {
    let bytes = snap
        .encode()
        .map_err(|e| std::io::Error::other(format!("encode: {e}")))?;
    publish_run_bytes(state_dir, &bytes, run_uuid, None)
}

pub fn publish_run_signed_bytes(
    state_dir: &Path,
    bytes: &[u8],
    run_uuid: &str,
    signature: &guard_core::SnapshotSignatureV1,
) -> std::io::Result<PublishedSnapshot> {
    publish_run_bytes(state_dir, bytes, run_uuid, Some(signature))
}

fn publish_run_bytes(
    state_dir: &Path,
    bytes: &[u8],
    run_uuid: &str,
    signature: Option<&guard_core::SnapshotSignatureV1>,
) -> std::io::Result<PublishedSnapshot> {
    publish_run_inner(state_dir, bytes, run_uuid, signature)
}

fn publish_run_inner(
    state_dir: &Path,
    bytes: &[u8],
    run_uuid: &str,
    signature: Option<&guard_core::SnapshotSignatureV1>,
) -> std::io::Result<PublishedSnapshot> {
    ensure_runs_dir(state_dir)?;

    // Snapshot file: tmp + fsync + rename.
    let tmp = run_snapshot_tmp_path(state_dir, run_uuid);
    let final_path = run_snapshot_path(state_dir, run_uuid);
    // Best-effort cleanup of any leftover tmp from an interrupted prior run.
    let _ = std::fs::remove_file(&tmp);
    {
        let mut f = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(PER_RUN_ARTIFACT_MODE)
            .open(&tmp)?;
        f.write_all(bytes)?;
        f.sync_all()?;
    }
    std::fs::rename(&tmp, &final_path)?;

    let digest = Sha256::digest(bytes);
    let digest_hex = hex_lower(&digest);

    // Manifest file: tmp + fsync + rename.
    let manifest_tmp = run_manifest_tmp_path(state_dir, run_uuid);
    let manifest_final = run_manifest_path(state_dir, run_uuid);
    let _ = std::fs::remove_file(&manifest_tmp);
    {
        let mut f = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(PER_RUN_ARTIFACT_MODE)
            .open(&manifest_tmp)?;
        let mut body = format!("{}\ndigest={}\n", final_path.display(), digest_hex);
        if let Some(signature) = signature {
            body.push_str(&format!("snapshot_signature_scheme={}\n", signature.scheme));
            body.push_str(&format!("snapshot_signer_kind={}\n", signature.signer_kind));
            body.push_str(&format!(
                "snapshot_public_key_sha256={}\n",
                signature.public_key_sha256
            ));
            body.push_str(&format!(
                "snapshot_public_key_x963={}\n",
                hex_lower(&signature.public_key_x963)
            ));
            body.push_str(&format!(
                "snapshot_signature_der={}\n",
                hex_lower(&signature.signature_der)
            ));
            body.push_str(&format!(
                "snapshot_signed_payload_sha256={}\n",
                signature.signed_payload_sha256
            ));
            body.push_str(&format!(
                "snapshot_signature_created_at_unix_ms={}\n",
                signature.signature_created_at_unix_ms
            ));
        }
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
