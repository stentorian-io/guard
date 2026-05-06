//! Smoke test: handle_status returns StatusReply::Ok with daemon-computed daemon_state.
//! Full state-transition coverage in plan 03-14 e2e (status_states.rs).

#[test]
fn handle_status_signature_compiles() {
    // Type-check only: handler accepts &DaemonState and returns StatusReply.
    let _ = sentinel_daemon::handlers::status::handle_status;
}

// WARNING #6 acceptance — daemon-side Degraded determination unit test.
// The decision logic is extracted into a pure function:
// `pub fn compute_daemon_state(recent_gaps: &[GapInfo], snapshot_failed: bool, now_ms: u64) -> DaemonStateKind`

#[test]
fn compute_daemon_state_degraded_on_recent_gap() {
    use sentinel_daemon::handlers::status::compute_daemon_state;
    use sentinel_ipc::{DaemonStateKind, GapInfo};
    let now = 1_700_000_000_000u64;
    let recent = vec![GapInfo {
        run_uuid: "r1".into(),
        gap_kind: "hardened-runtime".into(),
        binary_path: None,
        detected_at_ms: now - 1000, // 1 sec ago
    }];
    assert!(matches!(
        compute_daemon_state(&recent, false, now),
        DaemonStateKind::Degraded
    ));
}

#[test]
fn compute_daemon_state_degraded_on_snapshot_failed() {
    use sentinel_daemon::handlers::status::compute_daemon_state;
    use sentinel_ipc::DaemonStateKind;
    let now = 1_700_000_000_000u64;
    assert!(matches!(
        compute_daemon_state(&[], true, now),
        DaemonStateKind::Degraded
    ));
}

#[test]
fn compute_daemon_state_operational_when_clean() {
    use sentinel_daemon::handlers::status::compute_daemon_state;
    use sentinel_ipc::DaemonStateKind;
    let now = 1_700_000_000_000u64;
    assert!(matches!(
        compute_daemon_state(&[], false, now),
        DaemonStateKind::Operational
    ));
}

#[test]
fn compute_daemon_state_operational_when_gap_older_than_24h() {
    use sentinel_daemon::handlers::status::compute_daemon_state;
    use sentinel_ipc::{DaemonStateKind, GapInfo};
    let now = 1_700_000_000_000u64;
    let old = vec![GapInfo {
        run_uuid: "r1".into(),
        gap_kind: "hardened-runtime".into(),
        binary_path: None,
        detected_at_ms: now - 25 * 60 * 60 * 1000, // 25 hours ago
    }];
    assert!(matches!(
        compute_daemon_state(&old, false, now),
        DaemonStateKind::Operational
    ));
}
