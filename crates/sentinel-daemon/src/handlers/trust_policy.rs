//! TrustPolicy handler (D-38).
//!
//! Inserts a (path, sha256) tuple into the SQLite trusted_policy_files table.
//! DEFENSE-IN-DEPTH (T-02-06a-01): re-hashes the file on disk at handler time
//! and rejects if the wire-claimed sha256 disagrees — catches a CLI that lied
//! about the hash.
//!
//! BLOCKER-03 fix (Phase 2 review): canonicalize the wire-supplied `path` on
//! the daemon side and reject if the canonical form differs from what the
//! caller sent. Previously, the daemon trusted the wire string verbatim
//! (sentinel-cli does canonicalize before sending, but LOCAL_PEERTOKEN auth
//! does not pin the peer's executable identity — any local process running
//! as the same UID can issue TrustPolicy IPC). Combined with the in-tree
//! `find_sentinel_toml` walker that DOES canonicalize via `Path::canonicalize`
//! during PrepareSnapshot, accepting non-canonical paths here meant a
//! relative-path-laundering or symlink-race attack could pre-populate
//! `trusted_policy_files` with a row whose lookup key matched the canonical
//! form found at PrepareSnapshot time.
//!
//! With this fix, the daemon canonicalizes once and rejects any non-canonical
//! input before touching SQLite. The `INSERT OR REPLACE` row in
//! `rule_store.rs` is also better-behaved: `/x/proj/.sentinel.toml` and
//! `/x/proj/./.sentinel.toml` can no longer create distinct rows for the
//! same file.

use crate::policy_file::sha256_of_file;
use crate::rule_store::RuleStore;
use sentinel_ipc::TrustPolicyReply;
use std::path::Path;
use tracing::{info, warn};

pub fn handle_trust_policy(
    path: &str,
    claimed_sha256: &str,
    rule_store: &RuleStore,
) -> TrustPolicyReply {
    let p = Path::new(path);
    // BLOCKER-03 fix: canonicalize on the daemon side. Reject non-canonical
    // wire input so the SQLite key is always the canonical absolute path.
    let canonical = match p.canonicalize() {
        Ok(c) => c,
        Err(e) => {
            return TrustPolicyReply::err(format!("canonicalize {path}: {e}"));
        }
    };
    let canonical_str = canonical.display().to_string();
    if canonical_str != path {
        warn!(
            wire_path = %path,
            canonical = %canonical_str,
            "TrustPolicy path is not canonical — rejecting"
        );
        return TrustPolicyReply::err(format!(
            "path not canonical (got {path}, canonical {canonical_str})"
        ));
    }
    let actual_sha = match sha256_of_file(&canonical) {
        Ok(s) => s,
        Err(e) => {
            return TrustPolicyReply::err(format!("read+hash {canonical_str}: {e}"));
        }
    };
    if actual_sha != claimed_sha256 {
        warn!(
            path = %canonical_str,
            claimed = %claimed_sha256,
            actual = %actual_sha,
            "TrustPolicy hash mismatch — rejecting"
        );
        return TrustPolicyReply::err(format!(
            "hash mismatch (claimed {claimed_sha256}, actual {actual_sha})"
        ));
    }
    if let Err(e) = rule_store.insert_trusted(&canonical_str, &actual_sha, "cli") {
        return TrustPolicyReply::err(format!("rule_store insert: {e}"));
    }
    info!(path = %canonical_str, sha = %actual_sha, "TrustPolicy OK");
    TrustPolicyReply::ok()
}
