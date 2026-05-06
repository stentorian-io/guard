//! crates/sentinel-daemon/src/handlers/status.rs
//!
//! Phase 3 plan 03-08 — Status IPC handler (CLI-02 / D-69..D-72).
//!
//! Assembles a StatusReply from the current DaemonState. The daemon_state field
//! is computed here (WARNING #6 fix): Degraded if any recent_gap within 24h OR
//! last_snapshot_publish_failed flag is set; Operational otherwise.
//! StaleFeeds is reserved for Phase 4 per D-70 and never emitted here.

use std::sync::atomic::Ordering;

use sentinel_ipc::{
    DaemonStateKind, FeedInfo, GapInfo, InstallInfo, StatusCounters, StatusReply, TrackedRootInfo,
};

use crate::ipc_server::DaemonState;

const ONE_DAY_MS: u64 = 24 * 60 * 60 * 1000;

/// Main IPC handler. Called from ipc_server.rs dispatch arm 0x09 (MessageTag::Status).
pub fn handle_status(state: &DaemonState) -> StatusReply {
    // tracked_roots from process_tree.list_runs()
    let tracked_roots: Vec<TrackedRootInfo> = state
        .process_tree
        .list_runs()
        .into_iter()
        .map(|run| TrackedRootInfo {
            run_uuid: run.run_uuid,
            audit_token: sentinel_ipc::AuditTokenWire::from(run.tracked_root),
            argv: vec![],      // argv not stored on RunRecord in Phase 3; CLI renders as "unknown"
            started_at_ms: 0,  // not stored on RunRecord in Phase 3
        })
        .collect();

    let recent_gaps = state.recent_gaps.snapshot();

    // counters from rule_store + log_writer
    let (blocks, allows, gaps) = state.log_writer.counters_snapshot();
    let counters = StatusCounters {
        rules_user: state.rule_store.count_user_rules().unwrap_or(0),
        rules_trusted_toml: state.rule_store.count_trusted().unwrap_or(0),
        blocks_today: blocks,
        allows_today: allows,
        gaps_today: gaps,
    };

    // feeds: empty in Phase 3 (Phase 4 reserved per D-70)
    let feeds: Vec<FeedInfo> = vec![];

    // install_info: from install_artifact_store.list_all()
    let install_info = match state.install_artifact_store.list_all() {
        Ok(artifacts) if !artifacts.is_empty() => Some(InstallInfo {
            version: env!("CARGO_PKG_VERSION").to_string(),
            installed_at_ms: artifacts.iter().map(|a| a.installed_at_ms).min().unwrap_or(0),
            artifacts,
        }),
        _ => None,
    };

    // WARNING #6 fix: daemon-computed daemon_state.
    // StaleFeeds reserved for Phase 4 per D-70 — never emitted here.
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);
    let snapshot_failed = state
        .last_snapshot_publish_failed
        .load(Ordering::Relaxed);
    let daemon_state = compute_daemon_state(&recent_gaps, snapshot_failed, now_ms);

    StatusReply::ok(daemon_state, tracked_roots, recent_gaps, counters, feeds, install_info)
}

/// Pure function for unit testing the Degraded-determination logic.
///
/// Phase 3 emits only Operational or Degraded from this handler.
/// StaleFeeds is reserved for Phase 4 per D-70 and never appears here.
pub fn compute_daemon_state(
    recent_gaps: &[GapInfo],
    snapshot_failed: bool,
    now_ms: u64,
) -> DaemonStateKind {
    let recent_gap_within_24h = recent_gaps
        .iter()
        .any(|g| now_ms.saturating_sub(g.detected_at_ms) < ONE_DAY_MS);
    if recent_gap_within_24h || snapshot_failed {
        DaemonStateKind::Degraded
    } else {
        DaemonStateKind::Operational
    }
}
