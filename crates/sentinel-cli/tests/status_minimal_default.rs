//! Phase 3 plan 03-10 — minimal-default rendering smoke test.
//!
//! Full state-coverage in plan 03-14 e2e (status_states.rs).

use sentinel_cli::status::run_status;

#[test]
fn status_returns_2_when_db_absent_no_daemon() {
    // No daemon, no DB → NotInstalled → exit 2.
    let dir = tempfile::tempdir().unwrap();
    let sock = dir.path().join("nonexistent.sock");
    let state_dir = dir.path().join("state"); // does not exist
    let rc = run_status(&sock, &state_dir, false, false).unwrap();
    assert_eq!(rc, 2);
}

#[test]
fn status_returns_2_when_db_present_no_daemon() {
    let dir = tempfile::tempdir().unwrap();
    let sock = dir.path().join("nonexistent.sock");
    let state_dir = dir.path().join("state");
    std::fs::create_dir_all(&state_dir).unwrap();
    std::fs::write(state_dir.join("sentinel.db"), b"fake-db").unwrap();
    let rc = run_status(&sock, &state_dir, false, false).unwrap();
    assert_eq!(rc, 2); // DaemonNotRunning still exits 2 — daemon is required for "operational"
}
