#![cfg(target_os = "macos")]

//! Live-network e2e for ENF-07 closure (gap-closure 02-08).
//!
//! Mirrors 02-07-PLAN.md:99 precedent: live-network tests are
//! #[ignore]'d to avoid CI flakiness, opt-in via `cargo test -- --ignored`.
//!
//! The hermetic positive control for the Resolve-IPC plumbing lives in
//! crates/guard-hook/tests/resolve_client_tests.rs (added by Task 2);
//! this file is the empirical-confirmation surface for the full end-to-end
//! path including real DNS resolution and live network connectivity.
//!
//! ## Why this file has only #[ignore]'d live-network tests
//!
//! The cleanest hermetic positive-control would require the connect target to
//! be loopback (so a real listener can accept) — but Tier 0a fires for loopback
//! BEFORE the cache-miss Resolve-IPC path, so Resolve-IPC never runs for that
//! destination. Earlier designs considered:
//!   - `STT_GUARD_TEST_RESOLVE_OVERRIDE` env-var on the daemon — abandoned because
//!     handlers/resolve.rs is FROZEN per must-have #8.
//!   - Wall-clock timing against an unrouteable IP — too flaky across CI runners.
//!     The unit-level test in `resolve_client_tests.rs` is the chosen hermetic vehicle.
//!     This file covers the empirical opt-in confirmation path.

#[cfg_attr(
    not(target_os = "macos"),
    ignore = "macOS-only; live-network requires real DNS + reachable registry.npmjs.org / pypi.org"
)]
#[cfg_attr(
    target_os = "macos",
    ignore = "live-network: requires real DNS + reachable registry.npmjs.org / pypi.org"
)]
#[test]
fn pip_install_real_registry_succeeds_under_guard_run() {
    use guard_e2e::{DaemonHarness, resolve_cli, resolve_dylib};
    use std::process::Command;

    // Skip if pip3 is not on PATH.
    let pip_check = Command::new("sh").args(["-c", "which pip3"]).output();
    match pip_check {
        Ok(o) if o.status.success() => {}
        _ => {
            eprintln!("SKIPPED: pip3 not on PATH — install pip3 to run this live-network test");
            return;
        }
    }

    let cli = resolve_cli();
    let dylib = resolve_dylib();
    let harness = DaemonHarness::start().expect("start daemon harness");

    // Use `pip download` instead of `pip install --dry-run` because
    // --dry-run requires pip 22.2+ but Xcode's bundled pip is 21.2.4.
    // pip download exercises the same libc connect path to pypi.org.
    let download_dir = tempfile::tempdir().expect("tempdir for pip download");
    let output = Command::new(&cli)
        .arg("wrap")
        .arg("pip3")
        .args([
            "download",
            "--no-deps",
            "-d",
            download_dir.path().to_str().unwrap(),
            "requests",
        ])
        .env_clear()
        .env("HOME", harness.home.path())
        .env("PATH", std::env::var_os("PATH").unwrap_or_default())
        .env("STT_GUARD_HOOK_DYLIB", &dylib)
        .env("STT_GUARD_STATE_DIR", &harness.state_dir)
        .output()
        .expect("run stt-guard cli");

    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(
        output.status.success(),
        "pip download requests must succeed under stt-guard wrap\n\
         exit: {:?}\n\
         stderr: {}",
        output.status.code(),
        stderr
    );

    assert!(
        !stderr.contains("Verdict::Deny"),
        "pypi.org must NOT be denied under stt-guard wrap (ENF-07 closure)\n\
         stderr: {stderr}"
    );
}

#[cfg_attr(
    not(target_os = "macos"),
    ignore = "macOS-only; live-network requires real DNS + reachable curl + registry.npmjs.org"
)]
#[cfg_attr(
    target_os = "macos",
    ignore = "live-network: requires real DNS + reachable curl + registry.npmjs.org"
)]
#[test]
fn curl_get_real_registry_succeeds_under_guard_run() {
    use guard_e2e::{DaemonHarness, resolve_cli, resolve_dylib};
    use std::process::Command;

    let cli = resolve_cli();
    let dylib = resolve_dylib();
    let harness = DaemonHarness::start().expect("start daemon harness");

    let output = Command::new(&cli)
        .arg("wrap")
        .arg("/usr/bin/curl")
        .args([
            "--max-time",
            "10",
            "-sS",
            "-o",
            "/dev/null",
            "-w",
            "%{http_code}",
            "https://registry.npmjs.org/lodash",
        ])
        .env_clear()
        .env("HOME", harness.home.path())
        .env("PATH", std::env::var_os("PATH").unwrap_or_default())
        .env("STT_GUARD_HOOK_DYLIB", &dylib)
        .env("STT_GUARD_STATE_DIR", &harness.state_dir)
        .output()
        .expect("run stt-guard cli");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(
        output.status.success(),
        "curl to registry.npmjs.org must succeed under stt-guard wrap\n\
         exit: {:?}\n\
         stdout (http_code): {}\n\
         stderr: {}",
        output.status.code(),
        stdout,
        stderr
    );

    // HTTP status code written to stdout by -w "%{http_code}".
    let http_code: u16 = stdout.trim().parse().unwrap_or(0);
    assert!(
        (200..400).contains(&http_code),
        "expected HTTP 2xx/3xx from registry.npmjs.org; got {http_code}\n\
         stderr: {stderr}"
    );

    assert!(
        !stderr.contains("Verdict::Deny"),
        "registry.npmjs.org must NOT be denied under stt-guard wrap (ENF-07 closure)\n\
         stderr: {stderr}"
    );
}
