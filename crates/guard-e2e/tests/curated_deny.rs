#![cfg(target_os = "macos")]

//! ALLOW-06 abuse-pattern deny e2e test.
//!
//! `*.workers.dev` is in the curated YAML deny list (
//! `crates/guard-core/data/malicious-curated.yaml`). A wrapped
//! Node connect attempt to `guard-test.workers.dev` MUST be denied — the
//! deny rule has tier=BuiltinDeny (Tier 0) and is non-overridable per D-26.
//!
//! Note: `guard-test.workers.dev` is a fictional subdomain that doesn't
//! exist in Cloudflare; we accept either Stentorian Guard-deny (EHOSTUNREACH from
//! suffix-match deny at the hostname layer) or NXDOMAIN-then-error from
//! the DNS-not-found path. The differential point with deny.rs is that the
//! deny here is at the SUFFIX-MATCH curated YAML layer, not at the
//! default-deny no-rule-match layer.
//!
//! This test SKIPs cleanly on machines without a usable Homebrew node (matches
//! v0.1 deny.rs pattern).

use guard_e2e::{DaemonHarness, cargo_workspace_root, resolve_cli, resolve_dylib, resolve_node};
use std::process::Command;

const DENY_HOST: &str = "guard-test.workers.dev";
const DENY_PORT: &str = "443";

#[cfg_attr(not(target_os = "macos"), ignore = "macOS-only test")]
#[test]
fn curated_yaml_workers_dev_deny_is_enforced() {
    let cli = resolve_cli();
    let dylib = resolve_dylib();
    let node = match resolve_node() {
        Ok(p) => p,
        Err(why) => {
            eprintln!("SKIP: {why}");
            return;
        }
    };
    let harness = DaemonHarness::start().expect("start daemon");
    let script = cargo_workspace_root().join("crates/guard-e2e/harness/connect_workers_dev.js");
    assert!(
        script.exists(),
        "harness script missing at {}",
        script.display()
    );

    let output = Command::new(&cli)
        .arg("wrap")
        .arg(&node)
        .arg(&script)
        .env_clear()
        .env("HOME", harness.home.path())
        .env("PATH", std::env::var_os("PATH").unwrap_or_default())
        .env("STT_GUARD_HOOK_DYLIB", &dylib)
        .env("STT_GUARD_STATE_DIR", &harness.state_dir)
        .env("STT_GUARD_TEST_DENY_HOST", DENY_HOST)
        .env("STT_GUARD_TEST_DENY_PORT", DENY_PORT)
        .output()
        .expect("run stt-guard");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    // ALLOW-06 invariant: wrapped node MUST exit non-zero (workers.dev denied).
    assert!(
        !output.status.success(),
        "ALLOW-06 violation: wrapped node exited 0 (workers.dev not denied?)\n\
         host: {DENY_HOST}:{DENY_PORT}\n\
         stdout: {stdout}\n\
         stderr: {stderr}"
    );

    // Differential: exit code 1 means the JS harness saw EHOSTUNREACH or
    // ENOTFOUND — both consistent with Stentorian Guard-induced deny. Exit code 2
    // would mean an unexpected errno; that would surface a deeper bug.
    let code = output.status.code().unwrap_or(-1);
    assert_eq!(
        code, 1,
        "expected exit 1 (Stentorian Guard-deny errno class); got {code}\n\
         stdout: {stdout}\n\
         stderr: {stderr}"
    );

    // The harness's CONNECT-FAILED log line must be present (sock.on('error')
    // fired, which is the deny path).
    assert!(
        stdout.contains("CONNECT-FAILED"),
        "expected CONNECT-FAILED in script stdout (proves deny path fired); got: {stdout}"
    );

    // ECONNREFUSED would mean Stentorian Guard let the connect through to the network
    // layer — that's a regression (the curated deny rule must fire BEFORE
    // libc reaches the kernel).
    assert!(
        !stdout.contains("ECONNREFUSED"),
        "ECONNREFUSED means Stentorian Guard let workers.dev connect through to the \
         network layer — this is a deny-path regression. Got: {stdout}"
    );
}
