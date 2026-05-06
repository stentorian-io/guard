//! `.sentinel.toml` walk-up discovery, SHA-256 hashing, trust check.
//!
//! Decisions implemented here:
//!   - D-36: walk up from cwd, stop at first .sentinel.toml OR .git, depth cap 8.
//!   - D-40: closest-only — no chaining, no monorepo merge.
//!   - D-37: trust by (canonical_path, sha256) tuple in the SQLite table.
//!
//! The trust LOOKUP lives in rule_store.rs; this module orchestrates the
//! walk + hash + lookup pipeline that plan 02-06's PrepareSnapshot handler
//! calls per `sentinel run` invocation.

use sentinel_core::policy_file::{parse as parse_toml, PolicyFileError as ParseError, SentinelToml};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};

pub const MAX_DEPTH: usize = 8;

#[derive(Debug, thiserror::Error)]
pub enum PolicyFileError {
    #[error("walk-up from {0} found no .sentinel.toml")]
    NotFound(String),
    #[error("file at {path} is not trusted (hash {sha256} not in trusted_policy_files); run `sentinel trust-policy {path}` to honor it")]
    Untrusted { path: String, sha256: String },
    #[error("toml parse error in {path}: {msg}")]
    ParseError { path: String, msg: String },
    #[error("unsupported version {0}; only version=1 is accepted")]
    UnsupportedVersion(u16),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
}

/// Walk up from `start`, stopping at the first `.sentinel.toml` OR `.git`
/// encountered, depth-capped at MAX_DEPTH. Returns the canonicalized path of
/// the .sentinel.toml or None.
///
/// Symlink handling (Pitfall 5 in RESEARCH.md): canonicalize() resolves
/// symlinks once at the start; subsequent `.parent()` operates on the
/// canonical filesystem tree, so symlink loops cannot drive infinite walks.
pub fn find_sentinel_toml(start: &Path) -> Option<PathBuf> {
    let mut current = start.canonicalize().ok()?;
    for _ in 0..MAX_DEPTH {
        let toml_candidate = current.join(".sentinel.toml");
        if toml_candidate.exists() {
            return toml_candidate.canonicalize().ok();
        }
        let git_candidate = current.join(".git");
        if git_candidate.exists() {
            return None; // D-36 boundary: .git stops the walk
        }
        match current.parent() {
            Some(p) => current = p.to_owned(),
            None => break,
        }
    }
    None
}

/// SHA-256 of the file's content as 64-char lowercase hex.
pub fn sha256_of_file(path: &Path) -> std::io::Result<String> {
    let bytes = std::fs::read(path)?;
    let digest = Sha256::digest(&bytes);
    Ok(format!("{digest:x}"))
}

/// Parse the file at `path` into a SentinelToml. Maps the core parse errors
/// into the daemon's policy_file::PolicyFileError variants.
pub fn parse_file(path: &Path) -> Result<SentinelToml, PolicyFileError> {
    let content = std::fs::read_to_string(path)?;
    parse_toml(&content).map_err(|e| match e {
        ParseError::ParseError(msg) => PolicyFileError::ParseError {
            path: path.display().to_string(),
            msg,
        },
        ParseError::UnsupportedVersion(v) => PolicyFileError::UnsupportedVersion(v),
    })
}
