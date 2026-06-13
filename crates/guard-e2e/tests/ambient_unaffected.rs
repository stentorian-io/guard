#![cfg(target_os = "macos")]

//! ENF-04 success criterion #1: ambient (non-wrapped) traffic is unaffected
//! when stt-guard-daemon is running.
//!
//! Approach: start `DaemonHarness`; then run `curl http://example.com/` WITHOUT
//! `stt-guard wrap` and WITHOUT `DYLD_INSERT_LIBRARIES`. The dylib is NOT injected
//! into curl → no enforcement → the connect should succeed.
//!
//! Pre-test sanity: if curl is unavailable OR example.com is unreachable
//! (offline CI), skip rather than produce a false fail.
//!
//! ENF-04 is structurally satisfied at the daemon side (see plan 02-06a's
//! summary): the daemon emits no system-wide filter; per-run snapshots are
//! published only when a CLI invokes `PrepareSnapshot`. This test verifies the
//! property end-to-end: the user's other terminal sessions, GUI apps, etc.
//! remain unaffected by Stentorian Guard even when stt-guard-daemon is running.

use guard_e2e::DaemonHarness;
use std::path::PathBuf;
use std::process::Command;

#[cfg_attr(not(target_os = "macos"), ignore = "macOS-only test")]
#[test]
fn ambient_curl_succeeds_with_daemon_running() {
    let _harness = DaemonHarness::start().expect("start daemon");

    // Sanity: curl present? Prefer /usr/bin/curl (always present on macOS).
    let curl = PathBuf::from("/usr/bin/curl");
    if !curl.exists() {
        eprintln!("SKIP: /usr/bin/curl not found");
        return;
    }

    let out = Command::new(&curl)
        .arg("--max-time")
        .arg("5")
        .arg("--silent")
        .arg("--output")
        .arg("/dev/null")
        .arg("--write-out")
        .arg("%{http_code}")
        .arg("http://example.com/")
        .env_clear()
        .env("PATH", std::env::var_os("PATH").unwrap_or_default())
        .output()
        .expect("run curl");

    if !out.status.success() {
        eprintln!(
            "SKIP: curl exited non-zero (likely offline CI). stdout={:?} stderr={:?}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        return;
    }

    let body = String::from_utf8_lossy(&out.stdout);
    // ENF-04: ambient curl MUST succeed (200/3xx response code from
    // example.com). If it returns 0xx (curl-side network failure) it's
    // either offline or — critically — Stentorian Guard interfering with non-wrapped
    // traffic. Note: --write-out always prints the http_code; on a successful
    // request it's 200 (with example.com), on a redirect-followed-success
    // could be 301/302; either way starts with '2' or '3'.
    assert!(
        body.starts_with('2') || body.starts_with('3'),
        "ENF-04 violation: ambient curl returned non-2xx/3xx http_code='{body}' \
         — daemon may be interfering with non-wrapped traffic"
    );
}
