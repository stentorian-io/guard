//! TrustPolicy handler (D-38).
//!
//! Inserts a (path, sha256) tuple into the SQLite trusted_policy_files table.
//! DEFENSE-IN-DEPTH (T-02-06a-01): re-hashes the file on disk at handler time
//! and rejects if the wire-claimed sha256 disagrees — catches a CLI that lied
//! about the hash.

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
    let actual_sha = match sha256_of_file(p) {
        Ok(s) => s,
        Err(e) => {
            return TrustPolicyReply::err(format!("read+hash {path}: {e}"));
        }
    };
    if actual_sha != claimed_sha256 {
        warn!(
            path = %path,
            claimed = %claimed_sha256,
            actual = %actual_sha,
            "TrustPolicy hash mismatch — rejecting"
        );
        return TrustPolicyReply::err(format!(
            "hash mismatch (claimed {claimed_sha256}, actual {actual_sha})"
        ));
    }
    if let Err(e) = rule_store.insert_trusted(path, &actual_sha, "cli") {
        return TrustPolicyReply::err(format!("rule_store insert: {e}"));
    }
    info!(path = %path, sha = %actual_sha, "TrustPolicy OK");
    TrustPolicyReply::ok()
}
