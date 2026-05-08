//! crates/sentinel-daemon/src/handlers/delete_install_artifacts.rs
//!
//! Phase 07 plan 01 — DeleteInstallArtifacts handler (D-15 WARNING-5 fix).
//! Per-target removal IPC: the CLI calls this AFTER filesystem teardown
//! so the install_artifacts table no longer references files that no
//! longer exist.

use sentinel_ipc::{DeleteInstallArtifacts, DeleteInstallArtifactsReply};

use crate::install_artifacts::InstallArtifactStore;

pub fn handle_delete_install_artifacts(
    req: &DeleteInstallArtifacts,
    store: &InstallArtifactStore,
) -> DeleteInstallArtifactsReply {
    let mut total: u64 = 0;
    for kind in &req.kinds {
        match store.delete_by_kind(kind) {
            Ok(n) => total = total.saturating_add(n as u64),
            Err(e) => {
                return DeleteInstallArtifactsReply::err(format!(
                    "delete_by_kind({kind}): {e}"
                ));
            }
        }
    }
    DeleteInstallArtifactsReply::ok(total)
}
