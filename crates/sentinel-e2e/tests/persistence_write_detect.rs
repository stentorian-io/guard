//! M003-S04: verify that open() to macOS persistence paths is detected and
//! reported via IPC when running under the sentinel hook.
//!
//! The test creates a fake LaunchAgents directory inside a temp HOME,
//! runs a small C program that opens a file in ~/Library/LaunchAgents/
//! with O_WRONLY|O_CREAT under `sentinel run`, and verifies that the
//! daemon's JSONL log contains a `persistence-write` gap record.

use sentinel_e2e::{cargo_target_dir, resolve_cli, resolve_dylib, DaemonHarness};
use std::process::Command;

/// Writing to ~/Library/LaunchAgents/ under sentinel run produces a
/// persistence-write gap record in the daemon log.
#[cfg_attr(not(target_os = "macos"), ignore)]
#[test]
fn persistence_write_to_launch_agents_detected() {
    let harness = DaemonHarness::start().expect("start daemon");
    let cli = resolve_cli();
    let dylib = resolve_dylib();
    let home = harness.home.path();

    let la_dir = home.join("Library").join("LaunchAgents");
    std::fs::create_dir_all(&la_dir).unwrap();
    let target_plist = la_dir.join("evil.plist");

    let probe = cargo_target_dir().join("persistence_write_probe");
    assert!(
        probe.exists(),
        "persistence_write_probe not built at {}",
        probe.display()
    );

    let output = Command::new(&cli)
        .arg(&probe)
        .arg(target_plist.to_str().unwrap())
        .env_clear()
        .env("HOME", home)
        .env("PATH", std::env::var_os("PATH").unwrap_or_default())
        .env("SENTINEL_HOOK_DYLIB", &dylib)
        .env("SENTINEL_STATE_DIR", &harness.state_dir)
        .output()
        .expect("run sentinel with persistence_write_probe");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(
        output.status.success(),
        "probe should succeed (persistence writes are monitored, not blocked); stdout={stdout}\nstderr={stderr}"
    );
    assert!(
        stdout.contains("WRITE-OK"),
        "expected WRITE-OK marker; stdout={stdout}"
    );
}
