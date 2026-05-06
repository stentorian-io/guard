//! Phase 3 plan 03-14 — sentinel status across boot states.
//!
//! AC-STAT-01: Before install, `sentinel status` exits non-zero with "not-installed".
//! AC-STAT-02: --json emits parseable JSON object.
//! AC-STAT-03: After uninstall, status reverts to not-installed (covered by
//!             install_uninstall_roundtrip.rs end-to-end; here we test the
//!             not-installed detection logic directly via an empty state_dir).

use std::process::Command;

use sentinel_e2e::resolve_cli;

/// AC-STAT-01: Empty state_dir (no sentinel.db) → "not-installed" output + exit 2.
#[cfg(target_os = "macos")]
#[test]
fn status_before_install_says_not_installed() {
    let home = tempfile::tempdir().expect("home");
    let state_dir = home.path().join("Library/Application Support/Sentinel");
    std::fs::create_dir_all(&state_dir).ok();
    // No sentinel.db — the daemon was never installed.

    let cli = resolve_cli();
    let out = Command::new(&cli)
        .arg("status")
        .env_clear()
        .env("HOME", home.path())
        .env("PATH", std::env::var_os("PATH").unwrap_or_default())
        .env("SENTINEL_STATE_DIR", &state_dir)
        .output()
        .expect("sentinel status");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("not-installed"),
        "expected 'not-installed' in stdout, got: {stdout}"
    );
    // Exit code 2 = non-operational state (per run_status → render_offline → Ok(2)).
    assert_eq!(
        out.status.code(),
        Some(2),
        "exit code must be 2 for not-installed; stdout: {stdout}"
    );
}

/// AC-STAT-02: --json emits a parseable JSON object even when the daemon is not running.
#[cfg(target_os = "macos")]
#[test]
fn status_json_emits_parseable_object() {
    let home = tempfile::tempdir().expect("home");
    let state_dir = home.path().join("state");
    std::fs::create_dir_all(&state_dir).ok();

    let cli = resolve_cli();
    let out = Command::new(&cli)
        .arg("status")
        .arg("--json")
        .env_clear()
        .env("HOME", home.path())
        .env("PATH", std::env::var_os("PATH").unwrap_or_default())
        .env("SENTINEL_STATE_DIR", &state_dir)
        .output()
        .expect("sentinel status --json");
    let stdout = std::str::from_utf8(&out.stdout).expect("utf8");
    // Must be valid JSON with a "daemon_state" key.
    let value: serde_json::Value = serde_json::from_str(stdout.trim())
        .unwrap_or_else(|e| panic!("status --json must produce valid JSON: {e}\nstdout: {stdout}"));
    assert!(
        value.get("daemon_state").is_some(),
        "JSON missing 'daemon_state' key: {value}"
    );
}
