//! v0.5 — stale-feed failure mode.
//!
//! Verifies `sentinel status` correctly surfaces feeds that haven't been
//! pulled in > the freshness threshold.
//!
//! Approach:
//!   1. Start daemon (creates feed_metadata schema via migration).
//!   2. Stop daemon WITHOUT dropping state_dir
//!      (DaemonHarness::stop_preserving_state).
//!   3. Open the SQLite DB read-write and INSERT a feed_metadata row with
//!      last_pull_ms = now - 30 days (well past the freshness threshold) and
//!      last_pull_outcome = 'ok' (so StaleFeeds — not Degraded — fires per
//!      compute_daemon_state's path).
//!   4. Restart the daemon (StoppedHarness::restart_with_env) preserving the
//!      same state_dir AND PASSING SENTINEL_SKIP_FEED_FETCH=1 EXPLICITLY in
//!      the extra-env slice. Per WARNING-4 the test must NOT rely on
//!      DaemonHarness::start()'s implicit default — if the harness default
//!      ever changes, the daemon would fetch real feeds on restart and clobber
//!      our stale rows, silently breaking this test.
//!   5. Run `sentinel status --json` and HARD-assert daemon_state == "StaleFeeds".

use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

use sentinel_e2e::{resolve_cli, DaemonHarness};

#[cfg_attr(not(target_os = "macos"), ignore)]
#[test]
fn stale_feed_metadata_surfaces_warning_in_status() {
    // Step 1: start daemon to create the schema.
    let harness = DaemonHarness::start().expect("start daemon");
    let cli = resolve_cli();

    // Step 2: stop daemon, preserve state_dir + home.
    let stopped = harness
        .stop_preserving_state()
        .expect("stop_preserving_state");

    // Step 3: open DB read-write and INSERT a stale row.
    let db_path = stopped.state_dir.join("sentinel.db");
    let conn = rusqlite::Connection::open_with_flags(
        &db_path,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE,
    )
    .expect("open sentinel.db read-write");

    let now_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as i64;
    let stale_ms = now_ms - 30 * 24 * 60 * 60 * 1000; // 30 days ago

    // Per crates/sentinel-daemon/src/feed/store.rs:387-408 schema:
    //   feed | last_pull_ms | last_pull_outcome | last_commit_sha | schema_version_observed | error_message | record_count
    // last_pull_outcome must be 'ok' for StaleFeeds (not Degraded).
    conn.execute(
        "INSERT OR REPLACE INTO feed_metadata
         (feed, last_pull_ms, last_pull_outcome, last_commit_sha,
          schema_version_observed, error_message, record_count)
         VALUES ('OSV', ?1, 'ok', NULL, '1.7.4', NULL, 100)",
        rusqlite::params![stale_ms],
    )
    .expect("insert stale OSV row");
    conn.execute(
        "INSERT OR REPLACE INTO feed_metadata
         (feed, last_pull_ms, last_pull_outcome, last_commit_sha,
          schema_version_observed, error_message, record_count)
         VALUES ('GHSA', ?1, 'ok', NULL, '1.0', NULL, 50)",
        rusqlite::params![stale_ms],
    )
    .expect("insert stale GHSA row");
    drop(conn);

    // Step 4: restart daemon WITH SENTINEL_SKIP_FEED_FETCH=1 EXPLICITLY SET.
    //
    // Per WARNING-4: the test must NOT rely on DaemonHarness::start()'s
    // implicit default of SENTINEL_SKIP_FEED_FETCH=1. If the default ever
    // changes (or if restart_with_env doesn't propagate it), the daemon
    // would attempt a real feed fetch on startup, succeed, write fresh
    // last_pull_ms timestamps, and clobber our stale rows — silently
    // breaking this test. By passing the env explicitly we make the
    // hermetic-startup invariant load-bearing in this test file.
    let mut harness = stopped
        .restart_with_env(&[("SENTINEL_SKIP_FEED_FETCH", "1")])
        .expect("restart daemon with explicit SENTINEL_SKIP_FEED_FETCH=1");

    // Step 5: invoke `sentinel status --json` and parse the daemon_state.
    let out = Command::new(&cli)
        .arg("status")
        .arg("--json")
        .env_clear()
        .env("HOME", harness.home.path())
        .env("SENTINEL_STATE_DIR", &harness.state_dir)
        .env("PATH", std::env::var_os("PATH").unwrap_or_default())
        .output()
        .expect("run sentinel status --json");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let v: serde_json::Value = serde_json::from_str(stdout.trim()).unwrap_or_else(|e| {
        panic!(
            "expected JSON from sentinel status --json, got: {stdout}\nerr: {e}\nstderr: {}",
            String::from_utf8_lossy(&out.stderr)
        )
    });

    // status JSON envelope can be either {"Ok": {...}} (Result-shaped) or {...}
    // directly per crates/sentinel-e2e/tests/status_state_transitions.rs:88-100.
    let daemon_state = v
        .get("Ok")
        .and_then(|ok| ok.get("daemon_state"))
        .or_else(|| v.get("daemon_state"))
        .and_then(|x| x.as_str())
        .unwrap_or("");

    // Capture stderr defensively before the assertion so we can include it in
    // the panic message if the assertion fails.
    let drained = harness.drain_stderr();

    assert_eq!(
        daemon_state, "StaleFeeds",
        "HARD assertion failed: expected daemon_state=StaleFeeds, got '{daemon_state}'\n\
         status JSON: {v:#}\n\
         daemon stderr:\n{drained}",
    );

    drop(harness);
}
