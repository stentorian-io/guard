//! Phase 5 plan 05-06 — VAL-04 D-10 + CONTEXT C-05: hardened-binary failure mode.
//!
//! Verifies that when a wrapped command exec's into an Apple-signed
//! hardened-runtime binary, DYLD env vars are stripped and Sentinel detects
//! and surfaces the coverage gap. The gap appears in three places:
//!   - daemon stderr (tracing event with a coverage-gap marker)
//!   - JSONL log (Gap row with the recorded `gap_kind`)
//!   - `sentinel status --verbose` output (recent_gaps surface)
//!
use std::process::Command;
use std::time::Duration;

use sentinel_e2e::{
    DaemonHarness, cargo_target_dir, prepare_feed_fixture, resolve_cli, resolve_dylib,
};

#[cfg_attr(not(target_os = "macos"), ignore)]
#[test]
fn hardened_runtime_exec_surfaces_coverage_gap() {
    let cli = resolve_cli();
    let dylib = resolve_dylib();
    // Use a local file:// feed fixture instead of DaemonHarness::start()'s
    // default SENTINEL_SKIP_FEED_FETCH=1 (compiled out in --release builds).
    let (_feed_dir, feed_url) = prepare_feed_fixture("feed-mock-ua-parser-js");
    let mut harness = DaemonHarness::start_with_env(&[
        ("SENTINEL_FEED_URL_OVERRIDE_OSV", feed_url.as_str()),
        ("SENTINEL_FEED_URL_OVERRIDE_GHSA", feed_url.as_str()),
    ])
    .expect("start daemon");

    // Start Sentinel on a non-hardened helper so the hook loads, then have the
    // helper exec an Apple-signed hardened binary. Starting Sentinel directly
    // on the hardened binary strips DYLD before the hook can report anything.
    let probe = cargo_target_dir().join("hardened_exec_probe");
    assert!(
        probe.exists(),
        "hardened_exec_probe not built at {}",
        probe.display()
    );

    let out = Command::new(&cli)
        .arg("wrap")
        .arg(&probe)
        .arg("posix_spawn_env_delayed")
        .env_clear()
        .env("HOME", harness.home.path())
        .env("PATH", std::env::var_os("PATH").unwrap_or_default())
        .env("SENTINEL_HOOK_DYLIB", &dylib)
        .env("SENTINEL_STATE_DIR", &harness.state_dir)
        .output()
        .expect("run sentinel");
    // /usr/bin/env is allowed by policy and may succeed; the assertion is that
    // the daemon sees the child coverage gap after DYLD is stripped on spawn.
    eprintln!("[VAL-04 D-10] target exit: {:?}", out.status.code());
    eprintln!(
        "[VAL-04 D-10] target stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    // Allow gap_detector + log_writer mpsc to drain (env_not_propagated.rs
    // canon: 500ms margin).
    std::thread::sleep(Duration::from_millis(500));

    // -----------------------------------------------------------------------
    // ASSERTION 1: daemon stderr carries a tracing event mentioning the gap.
    // -----------------------------------------------------------------------
    let stderr = harness.drain_stderr();
    let stderr_lc = stderr.to_ascii_lowercase();
    let stderr_has_gap =
        stderr_lc.contains("hardened-runtime") || stderr_lc.contains("env-not-propagated");
    assert!(
        stderr_has_gap,
        "daemon stderr missing coverage-gap marker.\nstderr:\n{stderr}",
    );

    // -----------------------------------------------------------------------
    // ASSERTION 2: JSONL log carries a Gap row with the recorded gap_kind.
    // -----------------------------------------------------------------------
    let log = harness
        .home
        .path()
        .join("Library/Logs/Sentinel/sentinel.log");
    let content = std::fs::read_to_string(&log).unwrap_or_default();
    let has_gap_row = content.lines().any(|l| {
        l.contains(r#""gap_kind":"hardened-runtime""#)
            || l.contains(r#""gap_kind": "hardened-runtime""#)
            || l.contains(r#""gap_kind":"env-not-propagated""#)
            || l.contains(r#""gap_kind": "env-not-propagated""#)
    });
    assert!(
        has_gap_row,
        "no JSONL Gap row with hardened-runtime or env-not-propagated gap_kind;\n\
         log path: {}\n\
         contents:\n{content}\n\
         daemon stderr:\n{stderr}",
        log.display()
    );

    // -----------------------------------------------------------------------
    // ASSERTION 3: `sentinel status --verbose` surfaces the gap.
    // -----------------------------------------------------------------------
    let status_out = Command::new(&cli)
        .arg("status")
        .arg("--verbose")
        .env_clear()
        .env("HOME", harness.home.path())
        .env("SENTINEL_STATE_DIR", &harness.state_dir)
        .env("PATH", std::env::var_os("PATH").unwrap_or_default())
        .output()
        .expect("run sentinel status --verbose");
    let status_stdout = String::from_utf8_lossy(&status_out.stdout);
    let status_lc = status_stdout.to_ascii_lowercase();
    // WR-08: tighten ASSERTION 3. The previous predicate ('hardened' OR
    // 'gap') was too lenient — 'gap' is a broad word that could match any
    // unrelated text in verbose status output (e.g. 'language gap',
    // 'release gap', help-text mentioning gaps). Match the exact markers
    // that sentinel-cli/src/status.rs:188-197 emits:
    //   - 'Recent gaps (N):' header
    //   - the literal gap_kind printed in column 1
    // We require BOTH the section header AND the specific gap_kind, so a
    // pristine verbose status with no gaps does NOT pass.
    let has_recent_gaps_header = status_lc.contains("recent gaps");
    let has_gap_kind =
        status_lc.contains("hardened-runtime") || status_lc.contains("env-not-propagated");
    assert!(
        has_recent_gaps_header && has_gap_kind,
        "sentinel status --verbose did not surface the coverage gap;\n\
         expected: 'Recent gaps (' header AND a coverage gap_kind\n\
         has_recent_gaps_header={has_recent_gaps_header} \
         has_gap_kind={has_gap_kind}\n\
         status stdout:\n{status_stdout}\n\
         daemon stderr:\n{stderr}",
    );

    drop(harness);
}
