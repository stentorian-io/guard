//! E2E: `stt-guard status` emits human-readable state when daemon is running.

#[cfg(target_os = "macos")]
use std::process::Command;

#[cfg(target_os = "macos")]
use guard_e2e::{DaemonHarness, resolve_cli};

#[cfg(target_os = "macos")]
#[test]
fn status_emits_state_and_counters() {
    let harness = DaemonHarness::start().expect("start daemon");
    let cli = resolve_cli();
    let out = Command::new(&cli)
        .arg("status")
        .env_clear()
        .env("HOME", harness.home.path())
        .env("PATH", std::env::var_os("PATH").unwrap_or_default())
        .env("STT_GUARD_STATE_DIR", &harness.state_dir)
        .output()
        .expect("stt-guard status");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("State:"),
        "status output must contain 'State:' line; got: {stdout}"
    );
    assert!(
        stdout.contains("Counters:"),
        "status output must contain 'Counters:' section; got: {stdout}"
    );
}
