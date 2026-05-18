//! `.sentinel.toml` walk-up discovery, SHA-256 hashing, trust check.
//!
//! Decisions implemented here:
//!   - D-36: walk up from cwd, stop at first .sentinel.toml OR .git, depth cap 8.
//!   - D-40: closest-only — no chaining, no monorepo merge.
//!   - D-37: trust by (canonical_path, sha256) tuple in the SQLite table.
//!
//! The trust LOOKUP lives in rule_store.rs; this module orchestrates the
//! walk + hash + lookup pipeline that plan 02-06's PrepareSnapshot handler
//! calls per `sentinel wrap` invocation.

use sentinel_core::policy_file::{parse as parse_toml, PolicyFileError as ParseError, SentinelToml};
use sha2::{Digest, Sha256};
use std::path::Path;

// Phase 07 plan 02 (D-22 / Q12): `find_sentinel_toml` and `MAX_DEPTH` were
// lifted to `sentinel-core::policy_file` so the CLI can reuse the walker
// without depending on this crate. Re-exported here so existing daemon
// callers (`prepare_snapshot.rs`, `tests/policy_file_tests.rs`) continue
// to resolve `crate::policy_file::find_sentinel_toml` / `MAX_DEPTH`.
pub use sentinel_core::policy_file::{find_sentinel_toml, MAX_DEPTH};

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
