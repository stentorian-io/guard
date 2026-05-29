//! Smoke test: `handle_status` returns `StatusReply::Ok` with daemon-computed `daemon_state`.

#[test]
fn handle_status_signature_compiles() {
    let _ = guard_daemon::handlers::status::handle_status;
}

#[test]
fn compute_daemon_state_degraded_on_recent_gap() {
    use guard_daemon::handlers::status::compute_daemon_state;
    use guard_ipc::{DaemonStateKind, GapInfo};
    let now = 1_700_000_000_000u64;
    let recent = vec![GapInfo {
        run_uuid: "r1".into(),
        gap_kind: "hardened-runtime".into(),
        binary_path: None,
        detected_at_ms: now - 1000,
    }];
    assert!(matches!(
        compute_daemon_state(&recent, false, now),
        DaemonStateKind::Degraded
    ));
}

#[test]
fn compute_daemon_state_degraded_on_snapshot_failed() {
    use guard_daemon::handlers::status::compute_daemon_state;
    use guard_ipc::DaemonStateKind;
    let now = 1_700_000_000_000u64;
    assert!(matches!(
        compute_daemon_state(&[], true, now),
        DaemonStateKind::Degraded
    ));
}

#[test]
fn compute_daemon_state_operational_when_clean() {
    use guard_daemon::handlers::status::compute_daemon_state;
    use guard_ipc::DaemonStateKind;
    let now = 1_700_000_000_000u64;
    assert!(matches!(
        compute_daemon_state(&[], false, now),
        DaemonStateKind::Operational
    ));
}

#[test]
fn compute_daemon_state_operational_when_gap_older_than_24h() {
    use guard_daemon::handlers::status::compute_daemon_state;
    use guard_ipc::{DaemonStateKind, GapInfo};
    let now = 1_700_000_000_000u64;
    let old = vec![GapInfo {
        run_uuid: "r1".into(),
        gap_kind: "hardened-runtime".into(),
        binary_path: None,
        detected_at_ms: now - 25 * 60 * 60 * 1000,
    }];
    assert!(matches!(
        compute_daemon_state(&old, false, now),
        DaemonStateKind::Operational
    ));
}
