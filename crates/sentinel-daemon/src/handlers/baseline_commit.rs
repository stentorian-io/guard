//! crates/sentinel-daemon/src/handlers/baseline_commit.rs
//!
//! Phase 3 plan 03-08 — BaselineCommit handler (POL-04 / D-58, D-59, D-60).
//!
//! Called by `sentinel run --baseline` on tracked-root exit. Consumes the
//! per-run baseline_staging accumulator and returns it to the CLI together with
//! the existing closest .sentinel.toml (path + raw content) so the CLI can
//! render a unified diff and confirm with the user.
//!
//! DO NOT call sentinel-core::policy_file_writer here — the CLI side does the
//! actual append+atomic-write+TrustPolicy IPC. The daemon's role is purely to
//! RETURN the staging + existing-content; the CLI does the diff-confirm-write
//! loop in plan 03-13.

use sentinel_ipc::{BaselineCommit, BaselineCommitReply};

use crate::ipc_server::DaemonState;

pub fn handle_baseline_commit(req: &BaselineCommit, state: &DaemonState) -> BaselineCommitReply {
    let run = match state.process_tree.get_run(&req.run_uuid) {
        Some(r) => r,
        None => {
            return BaselineCommitReply::err(format!("no run record for {}", req.run_uuid))
        }
    };

    // Consume the accumulated baseline staging for this run (idempotent: None on re-call).
    let proposed = state.baseline_staging.take(&req.run_uuid).unwrap_or_default();

    // Determine existing_toml_path/content from the RunRecord (set at PrepareSnapshot time).
    let (existing_path, existing_content) = match run.project_toml_path.as_deref() {
        Some(p) => {
            // On read error, return path=Some, content=None so the CLI can render
            // "file disappeared" rather than treating it as fatal.
            let content = std::fs::read_to_string(p).ok();
            (Some(p.to_string()), content)
        }
        None => (None, None),
    };

    BaselineCommitReply::ok(proposed, existing_path, existing_content)
}
