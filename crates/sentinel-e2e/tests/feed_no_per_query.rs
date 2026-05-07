//! Phase 4 TI-08: bulk fetch only — per-query online lookups must never be
//! made.
//!
//! Strategy: instrument the daemon's fetcher to emit
//! `target = "sentinel.feed.fetch"` events on every network fetch attempt.
//! Run a sentinel run lifecycle that exercises `sentinel run` AND `sentinel
//! status` and assert:
//!
//!   1. `op="fetch_start"` events appear in daemon stderr only at
//!      PrepareSnapshot time (i.e. driven by `sentinel run`, NOT by `sentinel
//!      status` queries).
//!   2. No abuse.ch / osv.dev / api.github.com / threatfox / urlhaus
//!      hostnames appear in daemon stderr at all (covers the deferred
//!      abuse.ch feeds — verifies the deferral was respected in code as
//!      well as in docs).
//!   3. `sentinel status` between runs adds zero new fetch_start events
//!      (status reads feed_metadata SQLite; no gix call path).

use sentinel_e2e::{prepare_feed_fixture, resolve_cli, resolve_dylib, DaemonHarness};
use std::process::Command;

#[cfg_attr(not(target_os = "macos"), ignore)]
#[test]
fn block_decisions_do_not_trigger_per_query_online_lookups() {
    let (_fixture_tempdir, fixture_url) = prepare_feed_fixture("feed-mock-pol06");
    let cli = resolve_cli();
    let dylib = resolve_dylib();

    // Start daemon with RUST_LOG including the feed-fetch target.
    // tracing_subscriber's EnvFilter accepts dot-separated literal targets
    // as directives — `sentinel.feed.fetch=info` matches the
    // `tracing::info!(target = "sentinel.feed.fetch", ...)` events emitted
    // by feed::fetcher and feed::concurrency.
    let mut harness = DaemonHarness::start_with_env(&[
        ("RUST_LOG", "info,sentinel.feed.fetch=info"),
        ("SENTINEL_FEED_URL_OVERRIDE_OSV", fixture_url.as_str()),
        ("SENTINEL_FEED_URL_OVERRIDE_GHSA", fixture_url.as_str()),
    ])
    .expect("start daemon with tracing env");

    // First run: triggers PrepareSnapshot → 1 fetch per feed = 2 fetch_start
    // events (OSV + GHSA). Second run within SHARED_RESULT_TTL (5s) hits
    // D-86 cache — emits 0 fetch_start events but a fetch_cached_share event
    // instead. Total fetch_start count: 2 to 4 depending on TTL boundary.
    for i in 0..2 {
        let output = Command::new(&cli)
            .arg("run")
            .arg("--")
            .arg("/usr/bin/true")
            .env_clear()
            .env("HOME", harness.home.path())
            .env("PATH", std::env::var_os("PATH").unwrap_or_default())
            .env("SENTINEL_HOOK_DYLIB", &dylib)
            .env("SENTINEL_STATE_DIR", &harness.state_dir)
            .output()
            .expect("run sentinel");
        assert!(
            output.status.success(),
            "iteration {i} failed: stdout={}\nstderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
        );
    }

    // Drain daemon stderr and count `op="fetch_start"` occurrences. The
    // `op` field name is stable; tracing_subscriber emits it as
    // `op="fetch_start"` (with quotes around the &str value). ANSI color
    // codes wrap the field NAME (e.g. `\x1b[3mop\x1b[2m=\x1b[0m"fetch_start"`),
    // so we ANSI-strip first to make the substring assertion robust.
    let stderr_after_runs = strip_ansi(&harness.drain_stderr());
    let fetch_start_count_after_runs =
        stderr_after_runs.matches("op=\"fetch_start\"").count();

    // 2 feeds * up to 2 runs = 2..=4 fetch_start events. Less than 2 means
    // the fetcher didn't run (TI-01/02 broken). More than 4 means
    // fetch_start fires from somewhere other than fetch_one_feed (regression).
    assert!(
        fetch_start_count_after_runs >= 2 && fetch_start_count_after_runs <= 4,
        "Expected 2..=4 fetch_start events across the run loop; got {}\n\
         daemon stderr (truncated 4KB):\n{}",
        fetch_start_count_after_runs,
        &stderr_after_runs.chars().take(4096).collect::<String>(),
    );

    // CRITICAL TI-08 ASSERTION: a `sentinel status` invocation MUST NOT
    // trigger any new fetch_start events. status reads local feed_metadata
    // SQLite only — no gix call path. If this count grows, the daemon is
    // doing per-status-query fetches.
    let _status = Command::new(&cli)
        .arg("status")
        .arg("--json")
        .env_clear()
        .env("HOME", harness.home.path())
        .env("PATH", std::env::var_os("PATH").unwrap_or_default())
        .env("SENTINEL_STATE_DIR", &harness.state_dir)
        .output()
        .expect("run sentinel status");

    // Brief sleep so the daemon flushes any post-status tracing events.
    std::thread::sleep(std::time::Duration::from_millis(500));
    let stderr_after_status = strip_ansi(&harness.drain_stderr());
    let new_fetch_starts_during_status =
        stderr_after_status.matches("op=\"fetch_start\"").count();
    assert_eq!(
        new_fetch_starts_during_status, 0,
        "TI-08 violation: `sentinel status` triggered {} fetch_start event(s)\n\
         stderr after status:\n{}",
        new_fetch_starts_during_status, stderr_after_status,
    );

    // Negative assertion: the daemon never references per-query API
    // endpoints anywhere in stderr. This covers (a) osv.dev / api.github.com
    // (TI-08 — no per-query for the v1 feeds) AND (b) urlhaus / threatfox
    // (D-78 — confirms the abuse.ch deferral was respected in code, not
    // just in docs).
    let combined_stderr = format!("{stderr_after_runs}{stderr_after_status}");
    for forbidden in [
        "api.osv.dev",
        "api.github.com",
        "threatfox-api.abuse.ch",
        "urlhaus.abuse.ch",
        "urlhaus-api.abuse.ch",
    ] {
        assert!(
            !combined_stderr.contains(forbidden),
            "Daemon stderr must not reference per-query API endpoint {forbidden:?} (TI-08 / D-78 violation)\n\
             stderr (truncated 4KB):\n{}",
            &combined_stderr.chars().take(4096).collect::<String>(),
        );
    }
}

/// Strip ANSI escape sequences (`\x1b[...m`) so substring matches against
/// tracing-subscriber-formatted stderr work regardless of color settings.
/// (tracing_subscriber::fmt wraps field names in italic/dim escapes by
/// default, which breaks naive substring matches like `op="fetch_start"`.)
fn strip_ansi(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\x1b' && chars.peek() == Some(&'[') {
            chars.next(); // consume '['
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
