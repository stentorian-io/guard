//! crates/sentinel-cli/src/install/upgrade.rs
//!
//! Phase 3 plan 03-09 — idempotent upgrade-in-place (D-63).

use sentinel_ipc::InstallArtifact;

/// Diff existing artifacts against to-be-installed; returns (to_add, to_replace, to_remove).
pub fn diff(
    existing: &[InstallArtifact],
    proposed: &[(String, String, Option<String>)],   // (kind, target_path, content_hash)
) -> (Vec<usize>, Vec<usize>, Vec<usize>) {
    let mut to_add = Vec::new();
    let mut to_replace = Vec::new();
    for (i, (kind, path, hash)) in proposed.iter().enumerate() {
        if let Some(existing_row) = existing.iter().find(|a| &a.artifact_kind == kind && &a.target_path == path) {
            if existing_row.content_hash != *hash {
                to_replace.push(i);
            }
            // else: identical — no-op
        } else {
            to_add.push(i);
        }
    }
    let mut to_remove = Vec::new();
    for (j, row) in existing.iter().enumerate() {
        if !proposed.iter().any(|(k, p, _)| k == &row.artifact_kind && p == &row.target_path) {
            to_remove.push(j);
        }
    }
    (to_add, to_replace, to_remove)
}
