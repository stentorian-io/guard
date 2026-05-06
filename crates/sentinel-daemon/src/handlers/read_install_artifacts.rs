//! crates/sentinel-daemon/src/handlers/read_install_artifacts.rs
//!
//! Phase 3 plan 03-08 — ReadInstallArtifacts handler (CLI-06 sentinel uninstall).
//!
//! Reads the install artifacts manifest from the SQLite store and returns it to
//! the CLI for uninstall-path processing.

use sentinel_ipc::ReadInstallArtifactsReply;

use crate::install_artifacts::InstallArtifactStore;

pub fn handle_read_install_artifacts(store: &InstallArtifactStore) -> ReadInstallArtifactsReply {
    match store.list_all() {
        Ok(artifacts) => ReadInstallArtifactsReply::ok(artifacts),
        Err(e) => ReadInstallArtifactsReply::err(format!("install_artifacts read: {e}")),
    }
}
