//! E2E: sentinel status reports Operational when the daemon is running,
//! and --verbose includes the Counters section.

use std::process::Command;

use sentinel_e2e::{resolve_cli, DaemonHarness};

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
        .env("SENTINEL_STATE_DIR", &harness.state_dir)
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
fn status_json_with_running_daemon() {
    let harness = DaemonHarness::start().expect("start daemon");
    let cli = resolve_cli();
    let out = Command::new(&cli)
        .arg("status")
        .arg("--json")
        .env_clear()
        .env("HOME", harness.home.path())
        .env("PATH", std::env::var_os("PATH").unwrap_or_default())
        .env("SENTINEL_STATE_DIR", &harness.state_dir)
        .output()
        .expect("status --json");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let v: serde_json::Value = serde_json::from_str(stdout.trim())
        .unwrap_or_else(|e| panic!("expected valid JSON, got: {stdout}\nerr: {e}"));
    let kind = v
        .get("Ok")
        .and_then(|ok| ok.get("daemon_state"))
        .or_else(|| v.get("daemon_state"))
        .expect("daemon_state field in JSON")
        .as_str()
        .unwrap_or("");
    assert_eq!(
        kind, "Operational",
        "expected daemon_state='Operational', got: {kind} (full JSON: {v})"
    );
}

#[cfg(target_os = "macos")]
#[test]
fn status_verbose_includes_counters_section() {
    let harness = DaemonHarness::start().expect("start daemon");
    let cli = resolve_cli();
    let out = Command::new(&cli)
        .arg("status")
        .arg("--verbose")
        .env_clear()
        .env("HOME", harness.home.path())
        .env("PATH", std::env::var_os("PATH").unwrap_or_default())
        .env("SENTINEL_STATE_DIR", &harness.state_dir)
        .output()
        .expect("status --verbose");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("State: operational"),
        "--verbose missing State: line: {stdout}"
    );
    assert!(
        stdout.contains("Counters:"),
        "--verbose missing Counters: section: {stdout}"
    );
    assert_eq!(out.status.code(), Some(0));
}
