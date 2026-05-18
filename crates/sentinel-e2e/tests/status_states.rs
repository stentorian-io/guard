//! E2E: sentinel status --json emits parseable JSON when daemon is running.

use std::process::Command;

use sentinel_e2e::{resolve_cli, DaemonHarness};

#[cfg(target_os = "macos")]
#[test]
fn status_json_emits_parseable_object() {
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
        .expect("sentinel status --json");
    let stdout = std::str::from_utf8(&out.stdout).expect("utf8");
    let value: serde_json::Value = serde_json::from_str(stdout.trim())
        .unwrap_or_else(|e| panic!("status --json must produce valid JSON: {e}\nstdout: {stdout}"));
    let state = value
        .get("Ok")
        .and_then(|ok| ok.get("daemon_state"))
        .or_else(|| value.get("daemon_state"));
    assert!(state.is_some(), "JSON missing 'daemon_state' key: {value}");
}
