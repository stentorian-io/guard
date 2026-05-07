//! Phase 3 plan 03-17 (gap closure for UAT item #2) — sentinel status walks
//! the reachable DaemonStateKind variants end-to-end:
//!   NotInstalled → DaemonNotRunning → Operational
//!
//! The Degraded and StaleFeeds variants are covered by the render unit
//! tests in crates/sentinel-cli/src/status.rs (mod render_tests, plan
//! 03-17 Task 1) — Degraded requires a daemon-internal recent_gaps
//! injection that we deliberately do NOT expose as a public IPC, and
//! StaleFeeds is Phase 4-reserved (the daemon never emits it in Phase 3).

use std::process::Command;

use sentinel_e2e::{resolve_cli, DaemonHarness};

/// Walks NotInstalled → DaemonNotRunning → Operational. One ordered test
/// rather than three separate tests to keep the tempdir lifetime under one
/// fixture.
#[cfg(target_os = "macos")]
#[test]
fn status_walks_all_3_reachable_states_in_sequence() {
    // ---------- Step 1: NotInstalled ----------
    let home = tempfile::tempdir().expect("home");
    let state_dir = home.path().join("Library/Application Support/Sentinel");
    std::fs::create_dir_all(&state_dir).expect("create state_dir");

    let cli = resolve_cli();
    let out1 = Command::new(&cli)
        .arg("status")
        .env_clear()
        .env("HOME", home.path())
        .env("PATH", std::env::var_os("PATH").unwrap_or_default())
        .env("SENTINEL_STATE_DIR", &state_dir)
        .output().expect("status #1");
    let stdout1 = String::from_utf8_lossy(&out1.stdout);
    assert!(stdout1.contains("not-installed"),
        "Step 1 expected 'not-installed', got: {stdout1}");
    assert_eq!(out1.status.code(), Some(2),
        "Step 1 expected exit 2, got {:?}", out1.status.code());

    // ---------- Step 2: DaemonNotRunning ----------
    // Create an empty sentinel.db to simulate a prior install with a
    // currently-down daemon.
    let db_path = state_dir.join("sentinel.db");
    std::fs::write(&db_path, b"").expect("touch sentinel.db");

    let out2 = Command::new(&cli)
        .arg("status")
        .env_clear()
        .env("HOME", home.path())
        .env("PATH", std::env::var_os("PATH").unwrap_or_default())
        .env("SENTINEL_STATE_DIR", &state_dir)
        .output().expect("status #2");
    let stdout2 = String::from_utf8_lossy(&out2.stdout);
    assert!(stdout2.contains("daemon-not-running"),
        "Step 2 expected 'daemon-not-running', got: {stdout2}");
    assert_eq!(out2.status.code(), Some(2),
        "Step 2 expected exit 2, got {:?}", out2.status.code());

    // ---------- Step 3: Operational ----------
    // Spin up a real daemon. DaemonHarness creates its own state_dir under
    // /tmp (short path for socket) — we use harness.state_dir, not the
    // home-derived one above.
    let harness = DaemonHarness::start().expect("start daemon");
    let out3 = Command::new(&cli)
        .arg("status")
        .env_clear()
        .env("HOME", harness.home.path())
        .env("PATH", std::env::var_os("PATH").unwrap_or_default())
        .env("SENTINEL_STATE_DIR", &harness.state_dir)
        .output().expect("status #3");
    let stdout3 = String::from_utf8_lossy(&out3.stdout);
    assert!(stdout3.contains("operational"),
        "Step 3 expected 'operational', got: {stdout3}");
    assert_eq!(out3.status.code(), Some(0),
        "Step 3 expected exit 0, got {:?}; stderr: {}",
        out3.status.code(),
        String::from_utf8_lossy(&out3.stderr));

    // ---------- Step 4: Operational --json ----------
    let out4 = Command::new(&cli)
        .arg("status").arg("--json")
        .env_clear()
        .env("HOME", harness.home.path())
        .env("PATH", std::env::var_os("PATH").unwrap_or_default())
        .env("SENTINEL_STATE_DIR", &harness.state_dir)
        .output().expect("status --json");
    let stdout4 = String::from_utf8_lossy(&out4.stdout);
    let v: serde_json::Value = serde_json::from_str(stdout4.trim())
        .unwrap_or_else(|e| panic!("expected valid JSON, got: {stdout4}\nerr: {e}"));
    // StatusReply serializes as {"Ok": {"daemon_state": ...}} when daemon responds,
    // or as {"daemon_state": ...} (flat) from render_offline_to for offline states.
    let kind = v
        .get("Ok")
        .and_then(|ok| ok.get("daemon_state"))
        .or_else(|| v.get("daemon_state"))
        .expect("daemon_state field in JSON (top-level or nested under 'Ok')")
        .as_str()
        .unwrap_or("");
    assert_eq!(kind, "Operational",
        "Step 4 expected daemon_state='Operational', got: {kind} (full JSON: {v})");
    // Drop harness explicitly to terminate the daemon at end of test.
    drop(harness);
}

/// Step 5: --verbose vs minimal output differ. Asserts that --verbose
/// emits the documented "Counters:" header that minimal omits, against a
/// running daemon.
#[cfg(target_os = "macos")]
#[test]
fn status_verbose_includes_counters_section() {
    let harness = DaemonHarness::start().expect("start daemon");
    let cli = resolve_cli();
    let out = Command::new(&cli)
        .arg("status").arg("--verbose")
        .env_clear()
        .env("HOME", harness.home.path())
        .env("PATH", std::env::var_os("PATH").unwrap_or_default())
        .env("SENTINEL_STATE_DIR", &harness.state_dir)
        .output().expect("status --verbose");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("State: operational"),
        "--verbose missing State: line: {stdout}");
    assert!(stdout.contains("Counters:"),
        "--verbose missing Counters: section: {stdout}");
    assert_eq!(out.status.code(), Some(0));
}
