//! Phase 3 plan 03-14 e2e — install + uninstall round-trip leaves zero artifacts.
//!
//! AC-INST-06: After uninstall, no sentinel-managed artifacts remain under
//! the tempdir HOME (plist, init.sh, state_dir, log_dir all gone).
//!
//! Uses `--no-shell-integration` to avoid touching real rc files; pipes `y\n`
//! over stdin so the non-TTY confirm path fires (D-61/D-68 fallback).
//!
//! NOTE: This test exercises the non-TTY install path only. TTY-flow (MultiSelect
//! + spacebar-toggle) is out of v1 e2e scope (WARNING #12 in plan 03-14 SUMMARY).
//!
//! IMPORTANT: launchctl bootstrap/bootout require a running launchd user session.
//! On CI machines without a GUI session the bootstrap step may fail. The test is
//! `#[ignore]` so it is opt-in: `cargo test -p sentinel-e2e -- --ignored install_then_uninstall`.

use std::io::Write as _;
use std::process::{Command, Stdio};
use std::time::Duration;

use sentinel_e2e::resolve_cli;

#[cfg(target_os = "macos")]
#[test]
#[ignore = "requires launchd user session (GUI) + working daemon binary — opt-in via --ignored"]
fn install_then_uninstall_no_artifacts_remain() {
    let home = tempfile::tempdir().expect("home tempdir");
    // Use a short state dir under /tmp to avoid Unix socket path length limits.
    let state_tmp = tempfile::Builder::new()
        .prefix(".se2e")
        .tempdir_in("/tmp")
        .expect("state_dir tempdir");
    let state_dir = state_tmp.path().to_path_buf();

    let cli = resolve_cli();
    let daemon_bin = sentinel_e2e::cargo_target_dir().join("sentineld");
    if !daemon_bin.exists() {
        eprintln!("SKIP: sentineld binary not found at {} — run cargo build", daemon_bin.display());
        return;
    }

    // Run `sentinel install --no-shell-integration`.
    // Non-TTY: confirm prompt reads from piped stdin (D-61 fallback path).
    let mut child = Command::new(&cli)
        .arg("install")
        .arg("--no-shell-integration")
        .env_clear()
        .env("HOME", home.path())
        .env("PATH", std::env::var_os("PATH").unwrap_or_default())
        .env("SENTINEL_DAEMON_BINARY", &daemon_bin)
        .env("SENTINEL_STATE_DIR", &state_dir)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn sentinel install");
    if let Some(mut stdin) = child.stdin.take() {
        let _ = stdin.write_all(b"y\n");
    }
    let install_out = child.wait_with_output().expect("install wait");
    if !install_out.status.success() {
        eprintln!("stdout: {}", String::from_utf8_lossy(&install_out.stdout));
        eprintln!("stderr: {}", String::from_utf8_lossy(&install_out.stderr));
        panic!("sentinel install failed with status {:?}", install_out.status.code());
    }

    // Allow launchd bootstrap and daemon startup.
    std::thread::sleep(Duration::from_millis(500));

    // Assert: plist, init.sh, and sentinel.db exist after install.
    let plist = home.path().join("Library/LaunchAgents/com.sentinel.daemon.plist");
    let init_sh = home.path().join(".config/sentinel/init.sh");
    let db = state_dir.join("sentinel.db");
    assert!(plist.exists(), "launchagent plist missing after install: {}", plist.display());
    assert!(init_sh.exists(), "init.sh missing after install: {}", init_sh.display());
    assert!(db.exists(), "sentinel.db missing after install: {}", db.display());

    // Run `sentinel uninstall --force`.
    let uninstall_out = Command::new(&cli)
        .arg("uninstall")
        .arg("--force")
        .env_clear()
        .env("HOME", home.path())
        .env("PATH", std::env::var_os("PATH").unwrap_or_default())
        .env("SENTINEL_STATE_DIR", &state_dir)
        .output()
        .expect("sentinel uninstall");
    if !uninstall_out.status.success() {
        eprintln!("stdout: {}", String::from_utf8_lossy(&uninstall_out.stdout));
        eprintln!("stderr: {}", String::from_utf8_lossy(&uninstall_out.stderr));
        panic!("sentinel uninstall failed with status {:?}", uninstall_out.status.code());
    }
    // Allow launchd bootout to propagate.
    std::thread::sleep(Duration::from_millis(500));

    // Assert: all artifacts gone (AC-INST-06).
    assert!(!plist.exists(), "plist still present after uninstall: {}", plist.display());
    assert!(!init_sh.exists(), "init.sh still present after uninstall: {}", init_sh.display());
    assert!(!state_dir.exists(), "state_dir still present after uninstall: {}", state_dir.display());
    assert!(
        !home.path().join("Library/Logs/Sentinel").exists(),
        "log_dir still present after uninstall: {}",
        home.path().join("Library/Logs/Sentinel").display()
    );
}
