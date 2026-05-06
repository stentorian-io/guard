//! Phase 3 plan 03-11 — argument-shape and validation tests for sentinel approve.

use sentinel_cli::approve::{run_approve, ApproveArgs};

fn args(pattern: Option<&str>, suffix: bool, project: bool, from_log: Option<&str>, yes: bool) -> ApproveArgs {
    ApproveArgs {
        pattern: pattern.map(|s| s.into()),
        suffix, project,
        from_log: from_log.map(|s| s.into()),
        yes,
    }
}

#[test]
fn errors_when_no_pattern_and_no_from_log() {
    let dir = tempfile::tempdir().unwrap();
    let sock = dir.path().join("nonexistent.sock");
    let r = run_approve(&sock, args(None, false, false, None, true));
    assert!(r.is_err());
    let msg = format!("{}", r.err().unwrap());
    assert!(msg.contains("usage:") || msg.contains("hostname") || msg.contains("from-log"));
}

#[test]
fn errors_on_empty_pattern() {
    let dir = tempfile::tempdir().unwrap();
    let sock = dir.path().join("nonexistent.sock");
    let r = run_approve(&sock, args(Some("   "), false, false, None, true));
    assert!(r.is_err());
}

#[test]
fn errors_on_suffix_without_dot() {
    let dir = tempfile::tempdir().unwrap();
    let sock = dir.path().join("nonexistent.sock");
    let r = run_approve(&sock, args(Some("example.com"), true, false, None, true));
    assert!(r.is_err());
    let msg = format!("{}", r.err().unwrap());
    assert!(msg.contains("dot") || msg.contains("suffix"));
}

#[test]
fn machine_mode_attempts_ipc_call_via_unreachable_socket() {
    // Daemon not running; expect DaemonUnreachable error.
    let dir = tempfile::tempdir().unwrap();
    let sock = dir.path().join("nonexistent.sock");
    let r = run_approve(&sock, args(Some("foo.example.com"), false, false, None, true));
    assert!(r.is_err());
    let msg = format!("{}", r.err().unwrap());
    assert!(msg.to_lowercase().contains("daemon") || msg.to_lowercase().contains("unreach"),
            "expected DaemonUnreachable shape, got: {msg}");
}
