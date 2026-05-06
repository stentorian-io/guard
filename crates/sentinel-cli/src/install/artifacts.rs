//! crates/sentinel-cli/src/install/artifacts.rs
//!
//! Phase 3 plan 03-09 — install_artifacts read/write helpers.
//!
//! - Read: daemon IPC (preferred) → direct rusqlite (D-62 fallback)
//! - Write: direct rusqlite (no Insert IPC in v1; SQLite WAL handles concurrency)

use std::path::Path;

use sentinel_ipc::InstallArtifact;

use crate::CliError;

pub fn read_artifacts(sock: &Path, db_path: &Path) -> Result<Vec<InstallArtifact>, CliError> {
    match crate::ipc_client::read_install_artifacts_request(sock) {
        Ok(artifacts) => Ok(artifacts),
        Err(CliError::DaemonUnreachable(_)) => {
            // D-62 fallback.
            sentinel_daemon::install_artifacts::read_via_db(db_path)
                .map_err(|e| CliError::Other(format!("direct DB read: {e}")))
        }
        Err(other) => Err(other),
    }
}

pub fn record_artifact(
    db_path: &Path,
    kind: &str,
    target_path: &str,
    content_hash: Option<&str>,
    version: &str,
) -> Result<(), CliError> {
    // Open with RuleStore first to ensure migrations are applied (needed on first install).
    // If DB already exists and is migrated, this is a no-op migration.
    let _ = sentinel_daemon::rule_store::RuleStore::open(db_path)
        .map_err(|e| CliError::Other(format!("rule_store open: {e}")))?;
    let store = sentinel_daemon::install_artifacts::InstallArtifactStore::open(db_path)
        .map_err(|e| CliError::Other(format!("install_artifacts open: {e}")))?;
    store.insert(kind, target_path, content_hash, version)
        .map_err(|e| CliError::Other(format!("install_artifacts insert: {e}")))
}
