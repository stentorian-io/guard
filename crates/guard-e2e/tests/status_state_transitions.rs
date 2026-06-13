#![cfg(target_os = "macos")]

//! E2E: stt-guard status reports Operational when the daemon is running,
//! and includes the Counters section.

#[cfg(target_os = "macos")]
use std::process::Command;

#[cfg(target_os = "macos")]
use guard_e2e::{DaemonHarness, resolve_cli};

#[cfg(target_os = "macos")]
#[test]
fn status_operational_with_running_daemon() {
    let harness = DaemonHarness::start().expect("start daemon");
    let cli = resolve_cli();
    let out = Command::new(&cli)
        .arg("status")
        .env_clear()
        .env("HOME", harness.home.path())
        .env("PATH", std::env::var_os("PATH").unwrap_or_default())
        .env("STT_GUARD_STATE_DIR", &harness.state_dir)
        .output()
        .expect("status");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("operational"),
        "expected 'operational', got: {stdout}"
    );
    assert_eq!(
        out.status.code(),
        Some(0),
        "expected exit 0, got {:?}; stderr: {}",
        out.status.code(),
        String::from_utf8_lossy(&out.stderr)
    );
}

#[cfg(target_os = "macos")]
#[test]
fn status_reports_operational_state() {
    let harness = DaemonHarness::start().expect("start daemon");
    let cli = resolve_cli();
    let out = Command::new(&cli)
        .arg("status")
        .env_clear()
        .env("HOME", harness.home.path())
        .env("PATH", std::env::var_os("PATH").unwrap_or_default())
        .env("STT_GUARD_STATE_DIR", &harness.state_dir)
        .output()
        .expect("status");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("State: operational"),
        "expected 'State: operational' in output; got: {stdout}"
    );
}

#[cfg(target_os = "macos")]
#[test]
fn status_verbose_includes_counters_section() {
    let harness = DaemonHarness::start().expect("start daemon");
    let cli = resolve_cli();
    let out = Command::new(&cli)
        .arg("status")
        .env_clear()
        .env("HOME", harness.home.path())
        .env("PATH", std::env::var_os("PATH").unwrap_or_default())
        .env("STT_GUARD_STATE_DIR", &harness.state_dir)
        .output()
        .expect("status");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("State: operational"),
        "missing State: line: {stdout}"
    );
    assert!(
        stdout.contains("Counters:"),
        "missing Counters: section: {stdout}"
    );
    assert_eq!(out.status.code(), Some(0));
}
