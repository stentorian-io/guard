//! crates/guard-daemon/src/handlers/delete_install_artifacts.rs
//!
//! v0.7 — `DeleteInstallArtifacts` handler (WARNING-5 fix).
//! Per-target removal IPC: the CLI calls this AFTER filesystem teardown
//! so the `install_artifacts` table no longer references files that no
//! longer exist.

use guard_ipc::{DeleteInstallArtifacts, DeleteInstallArtifactsReply};

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
                return DeleteInstallArtifactsReply::err(format!("delete_by_kind({kind}): {e}"));
            }
        }
    }
    DeleteInstallArtifactsReply::ok(total)
}
