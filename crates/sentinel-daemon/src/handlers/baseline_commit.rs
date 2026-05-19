//! crates/sentinel-daemon/src/handlers/baseline_commit.rs
//!
//! v0.3 — BaselineCommit handler.
//!
//! Called by `sentinel wrap --baseline` on tracked-root exit. Consumes the
//! per-run baseline_staging accumulator and returns it to the CLI.

use sentinel_ipc::{BaselineCommit, BaselineCommitReply};

use crate::ipc_server::DaemonState;

pub fn handle_baseline_commit(req: &BaselineCommit, state: &DaemonState) -> BaselineCommitReply {
    let _run = match state.process_tree.get_run(&req.run_uuid) {
        Some(r) => r,
        None => {
            return BaselineCommitReply::err(format!("no run record for {}", req.run_uuid))
        }
    };

    // Consume the accumulated baseline staging for this run (idempotent: None on re-call).
    let proposed = state.baseline_staging.take(&req.run_uuid).unwrap_or_default();

    BaselineCommitReply::ok(proposed)
}
