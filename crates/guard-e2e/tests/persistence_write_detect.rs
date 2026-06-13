#![cfg(target_os = "macos")]

//! Verify that file writes to macOS persistence paths are detected and
//! logged as `persistence-write` gap records.
//!
//! The daemon's kqueue-based persistence watcher monitors directories like
//! ~/Library/LaunchAgents/ for file creation/modification. When a write
//! occurs during an active `stt-guard wrap` session, the daemon emits a gap
//! record to its JSONL log.
//!
//! This test creates ~/Library/LaunchAgents/ before the daemon starts (so
//! the watcher picks it up), runs `stt-guard wrap` with a probe that writes
//! a .plist file, and verifies the gap record appears in the log.

use guard_e2e::{DaemonHarness, resolve_cli, resolve_dylib, resolve_probe};
use std::path::Path;
use std::process::Command;

/// Writing to ~/Library/LaunchAgents/ under stt-guard wrap produces a
/// persistence-write gap record in the daemon log.
#[cfg_attr(not(target_os = "macos"), ignore = "macOS-only test")]
#[test]
fn persistence_write_to_launch_agents_detected() {
    let harness = DaemonHarness::start_with_env_and_home_setup(&[], |home| {
        // Pre-create the LaunchAgents directory so the daemon's persistence
        // watcher registers a kqueue watch at startup.
        std::fs::create_dir_all(home.join("Library").join("LaunchAgents"))?;
        Ok(())
    })
    .expect("start daemon");

    let cli = resolve_cli();
    let dylib = resolve_dylib();
    let home = harness.home.path();

    let la_dir = home.join("Library").join("LaunchAgents");
    let target_plist = la_dir.join("evil.plist");

    let probe = resolve_probe();

    let output = Command::new(&cli)
        .arg("wrap")
        .arg(&probe)
        .arg(target_plist.to_str().unwrap())
        .env_clear()
        .env("HOME", home)
        .env("PATH", std::env::var_os("PATH").unwrap_or_default())
        .env("STT_GUARD_HOOK_DYLIB", &dylib)
        .env("STT_GUARD_STATE_DIR", &harness.state_dir)
        .output()
        .expect("run stt-guard with persistence_write_probe");

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

    // The daemon's persistence watcher detects the write via kqueue. Give it
    // a moment to process the event and write to the JSONL log.
    let log_path = home.join("Library/Logs/Stentorian Guard/stt-guard.log");
    let found = wait_for_gap_record(&log_path, "persistence-write", 5);

    assert!(
        found,
        "expected persistence-write gap record in daemon log at {}",
        log_path.display()
    );
}

/// Poll the JSONL log for a gap record with the given `gap_kind`.
/// Returns true if found within `timeout_secs`.
fn wait_for_gap_record(log_path: &Path, gap_kind: &str, timeout_secs: u64) -> bool {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(timeout_secs);
    while std::time::Instant::now() < deadline {
        if let Ok(contents) = std::fs::read_to_string(log_path) {
            for line in contents.lines() {
                if line.contains("\"event\":\"gap\"") && line.contains(gap_kind) {
                    return true;
                }
            }
        }
        std::thread::sleep(std::time::Duration::from_millis(200));
    }
    false
}
