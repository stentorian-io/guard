//! crates/guard-daemon/src/handlers/status.rs
//!
//! Status IPC handler. Reports tracked roots, counters, gaps, and daemon health.

use std::sync::atomic::Ordering;

use guard_ipc::{
    DaemonStateKind, GapInfo, InstallInfo, StatusCounters, StatusReply, TrackedRootInfo,
};

use crate::ipc_server::DaemonState;

const ONE_DAY_MS: u64 = 24 * 60 * 60 * 1000;

pub fn handle_status(state: &DaemonState) -> StatusReply {
    let tracked_roots: Vec<TrackedRootInfo> = state
        .process_tree
        .list_runs()
        .into_iter()
        .map(|run| TrackedRootInfo {
            run_uuid: run.run_uuid,
            audit_token: guard_ipc::AuditTokenWire::from(run.tracked_root),
            argv: vec![],
            started_at_ms: 0,
        })
        .collect();

    let recent_gaps = state.recent_gaps.snapshot();

    let (blocks, allows, gaps) = state.log_writer.counters_snapshot();
    let counters = StatusCounters {
        rules_user: state.rule_store.count_user_rules().unwrap_or(0),
        blocks_today: blocks,
        allows_today: allows,
        gaps_today: gaps,
    };

    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);

    let install_info = match state.install_artifact_store.list_all() {
        Ok(artifacts) if !artifacts.is_empty() => Some(InstallInfo {
            version: env!("CARGO_PKG_VERSION").to_string(),
            installed_at_ms: artifacts
                .iter()
                .map(|a| a.installed_at_ms)
                .min()
                .unwrap_or(0),
            artifacts,
        }),
        _ => None,
    };

    let snapshot_failed = state.last_snapshot_publish_failed.load(Ordering::Relaxed);
    let daemon_state = compute_daemon_state(&recent_gaps, snapshot_failed, now_ms);

    StatusReply::ok(
        daemon_state,
        tracked_roots,
        recent_gaps,
        counters,
        install_info,
    )
}

pub fn compute_daemon_state(
    recent_gaps: &[GapInfo],
    snapshot_failed: bool,
    now_ms: u64,
) -> DaemonStateKind {
    let recent_gap_within_24h = recent_gaps
        .iter()
        .any(|g| now_ms.saturating_sub(g.detected_at_ms) < ONE_DAY_MS);
    if recent_gap_within_24h || snapshot_failed {
        return DaemonStateKind::Degraded;
    }
    DaemonStateKind::Operational
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compute_daemon_state_degraded_on_snapshot_failure() {
        let now = 1_700_000_000_000u64;
        assert!(matches!(
            compute_daemon_state(&[], true, now),
            DaemonStateKind::Degraded
        ));
    }

    #[test]
    fn compute_daemon_state_operational_when_healthy() {
        let now = 1_700_000_000_000u64;
        assert!(matches!(
            compute_daemon_state(&[], false, now),
            DaemonStateKind::Operational
        ));
    }

    #[test]
    fn compute_daemon_state_degraded_on_recent_gap() {
        let now = 1_700_000_000_000u64;
        let gap = GapInfo {
            run_uuid: "uuid".to_string(),
            gap_kind: "test".to_string(),
            binary_path: None,
            detected_at_ms: now - 1000,
        };
        assert!(matches!(
            compute_daemon_state(&[gap], false, now),
            DaemonStateKind::Degraded
        ));
    }
}
