//! Phase 4 TI-06: a feed record with schema_version 2.0.0 must trigger D-87's
//! "fail loudly" path: feed_metadata.last_pull_outcome = 'schema_unknown',
//! daemon_state Degraded, and a feed_error tracing event.

use sentinel_e2e::{prepare_feed_fixture, resolve_cli, resolve_dylib, DaemonHarness};
use std::process::Command;

#[cfg_attr(not(target_os = "macos"), ignore)]
#[test]
fn schema_unknown_2_0_0_raises_degraded_and_emits_feed_error() {
    let (_fixture_tempdir, fixture_url) = prepare_feed_fixture("feed-mock-bad-schema");
    let cli = resolve_cli();
    let dylib = resolve_dylib();
    let mut harness = DaemonHarness::start_with_env(&[
        ("SENTINEL_FEED_URL_OVERRIDE_OSV", fixture_url.as_str()),
        ("SENTINEL_FEED_URL_OVERRIDE_GHSA", fixture_url.as_str()),
    ])
    .expect("start daemon");

    // Trigger the fetch + parse path. Per D-87, schema-unknown does NOT
    // fail the run (last-good-cache fallback) — /usr/bin/true succeeds.
    // The signal lives in feed_metadata + daemon_state + tracing events.
    let run_out = Command::new(&cli)
        .arg("/usr/bin/true")
        .env_clear()
        .env("HOME", harness.home.path())
        .env("PATH", std::env::var_os("PATH").unwrap_or_default())
        .env("SENTINEL_HOOK_DYLIB", &dylib)
        .env("SENTINEL_STATE_DIR", &harness.state_dir)
        .output()
        .expect("run sentinel");
    assert!(
        run_out.status.success(),
        "sentinel run /usr/bin/true succeeds even with schema_unknown feed (D-87 last-good-cache path)\n\
         exit: {:?}\nstdout: {}\nstderr: {}",
        run_out.status.code(),
        String::from_utf8_lossy(&run_out.stdout),
        String::from_utf8_lossy(&run_out.stderr),
    );

    // Capture daemon stderr for the feed_error tracing event assertion below.
    // Drain BEFORE the status invocation so we only see the fetch's events.
    let daemon_stderr = harness.drain_stderr();

    // (a) feed_metadata.last_pull_outcome = 'schema_unknown' for OSV (the
    // fetcher writes this when ALL parse failures are SchemaUnknown — see
    // fetcher.rs `all_failures_schema_unknown`).
    let db_path = harness.state_dir.join("sentinel.db");
    let conn = rusqlite::Connection::open_with_flags(
        &db_path,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )
    .expect("open sentinel.db");
    let outcome: String = conn
        .query_row(
            "SELECT last_pull_outcome FROM feed_metadata WHERE feed = 'OSV'",
            [],
            |r| r.get(0),
        )
        .expect("query feed_metadata for OSV");
    assert_eq!(
        outcome, "schema_unknown",
        "OSV feed last_pull_outcome must be 'schema_unknown' for fixture with schema_version 2.0.0"
    );

    // (b) daemon stderr carries the W-9 structured tracing event (event=feed_error
    // kind=schema_unknown). tracing_subscriber::fmt's default writer emits
    // ANSI color escapes around field NAMES (so `event=` may appear as
    // `event[ansi]=[ansi]"feed_error"`). To be ANSI-tolerant we (1) strip
    // ANSI escapes via a tiny scanner and then (2) assert on the cleaned
    // substring.
    let stripped_stderr = strip_ansi(&daemon_stderr);
    assert!(
        stripped_stderr.contains("event=\"feed_error\"")
            || stripped_stderr.contains("event=feed_error"),
        "daemon stderr must contain a feed_error event\nstderr (ANSI-stripped, truncated 2KB):\n{}",
        &stripped_stderr.chars().take(2048).collect::<String>(),
    );
    assert!(
        stripped_stderr.contains("kind=\"schema_unknown\"")
            || stripped_stderr.contains("kind=schema_unknown"),
        "daemon stderr must contain kind=schema_unknown\nstderr (ANSI-stripped, truncated 2KB):\n{}",
        &stripped_stderr.chars().take(2048).collect::<String>(),
    );

    // (c) `sentinel status --json` reports daemon_state = Degraded.
    let status_output = Command::new(&cli)
        .arg("status")
        .arg("--json")
        .env_clear()
        .env("HOME", harness.home.path())
        .env("PATH", std::env::var_os("PATH").unwrap_or_default())
        .env("SENTINEL_STATE_DIR", &harness.state_dir)
        .output()
        .expect("run sentinel status");
    assert!(
        status_output.status.success() || status_output.status.code() == Some(0),
        "sentinel status --json failed: stderr={}",
        String::from_utf8_lossy(&status_output.stderr),
    );
    let stdout = String::from_utf8_lossy(&status_output.stdout);
    let v: serde_json::Value = serde_json::from_str(&stdout).expect("parse status JSON");
    let ok = v
        .get("Ok")
        .expect("StatusReply::Ok variant required (got: {stdout})");
    let daemon_state = ok
        .get("daemon_state")
        .and_then(|s| s.as_str())
        .unwrap_or("");
    assert_eq!(
        daemon_state, "Degraded",
        "daemon_state must be Degraded after schema_unknown failure: full status = {stdout}"
    );
}

/// Strip ANSI escape sequences (`\x1b[...m`) so substring matches against
/// tracing-subscriber-formatted stderr work regardless of color settings.
fn strip_ansi(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\x1b' && chars.peek() == Some(&'[') {
            chars.next(); // consume '['
            // Skip until 'm' (or any letter terminator); ANSI CSI is
            // `\x1b[ <params> <terminator>` where terminator is `@`..`~`.
            for next in chars.by_ref() {
                if next.is_ascii_alphabetic() {
                    break;
                }
            }
        } else {
            out.push(c);
        }
    }
    out
}
