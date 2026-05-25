//! Manifest writer.
//!
//! Format (text, 2+ lines):
//!   line 1: absolute path of the current snapshot CBOR file
//!   line 2: digest=<64-hex-char SHA-256 of the snapshot bytes>
//!   line 3+: ML-DSA snapshot signature metadata for per-run manifests
//!
//! Reader (dylib, plan 06) opens the manifest, parses these lines, opens
//! the snapshot path, computes SHA-256 of its bytes, verifies it matches the
//! manifest's digest, verifies the snapshot signature, and only then mmaps the
//! snapshot.

use crate::snapshot::PublishedSnapshot;
use crate::state_dir::{manifest_path, manifest_tmp_path};
use std::fs::OpenOptions;
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

pub fn write(state_dir: &Path, snap: &PublishedSnapshot) -> std::io::Result<()> {
    let tmp = manifest_tmp_path(state_dir);
    let final_path = manifest_path(state_dir);

    // Best effort: remove a leftover tmp from a previous interrupted run.
    let _ = std::fs::remove_file(&tmp);

    {
        let mut f = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&tmp)?;
        writeln!(f, "{}", snap.path.display())?;
        writeln!(f, "digest={}", snap.digest_hex)?;
        f.sync_all()?;
    }
    std::fs::rename(&tmp, &final_path)?;
    Ok(())
}

/// Reader-side helper: parses a manifest file's contents (NOT the path —
/// caller has already validated the path lives under state_dir).
pub fn parse(contents: &str) -> Result<ParsedManifest, ParseError> {
    let mut lines = contents.lines();
    let path = lines.next().ok_or(ParseError::MissingPath)?.to_string();
    let digest_line = lines.next().ok_or(ParseError::MissingDigest)?;
    let digest = digest_line
        .strip_prefix("digest=")
        .ok_or(ParseError::MalformedDigestLine)?;
    if digest.len() != 64 || !digest.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(ParseError::MalformedDigest);
    }
    Ok(ParsedManifest {
        snapshot_path: path,
        digest_hex: digest.to_string(),
    })
}

pub struct ParsedManifest {
    pub snapshot_path: String,
    pub digest_hex: String,
}

#[derive(Debug, thiserror::Error)]
pub enum ParseError {
    #[error("manifest missing path line")]
    MissingPath,
    #[error("manifest missing digest line")]
    MissingDigest,
    #[error("malformed digest line (expected 'digest=<hex>')")]
    MalformedDigestLine,
    #[error("digest is not 64 hex characters")]
    MalformedDigest,
}
