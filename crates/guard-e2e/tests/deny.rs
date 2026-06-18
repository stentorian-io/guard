#![cfg(target_os = "macos")]

//! Roadmap success criterion #2: a wrapped Node attempt to connect to a
//! non-allowlisted host is BLOCKED by the dylib (intercepted at
//! `connect()/getaddrinfo()` against the hand-coded allowlist) and the
//! wrapped command exits non-zero.
//!
//! DIFFERENTIAL ASSERTION:
//! The original test against `evil.example.com` could not distinguish
//! Stentorian Guard-deny from offline-DNS-NXDOMAIN: any real resolver returns
//! NXDOMAIN for that subdomain, surfacing in Node as ENOTFOUND -- exactly
//! the same error code the test was accepting as proof of Stentorian Guard-deny.
//! The remediation uses the strongest evidence pattern (differential):
//!
//!   - `node_connect_to_non_allowlisted_host_is_denied`: connects to
//!     `discord.com:443`. discord.com resolves successfully outside
//!     Stentorian Guard (real A records). NOT in D-18's v0.1 allowlist. The
//!     ONLY failure path is Stentorian Guard-induced. We assert the connect-time
//!     errno class is one of Stentorian Guard's deny errnos (EHOSTUNREACH from
//!     libc connect deny, `EAI_FAIL` from getaddrinfo deny -- surfaced by
//!     Node as ENOTFOUND for the `EAI_FAIL` path or EHOSTUNREACH for the
//!     connect path). NXDOMAIN cannot happen for a resolvable host so
//!     ENOTFOUND in this test is unambiguous evidence of Stentorian Guard firing
//!     at the getaddrinfo layer.
//!
//!   - `node_connect_to_loopback_is_denied`: connects to `127.0.0.1:9`.
//!     Loopback is local relay risk, so ISS-114 fails it closed before the
//!     kernel can return ECONNREFUSED.
//!
//! Target binary requirement: node must be NON-hardened-runtime (Pitfall 2;
//! spike A2). On macOS 26.x with Homebrew node, this is the case;
//! /usr/bin/python3 and Apple-shipped /bin/sh strip DYLD_*. The tests
//! invoke the resolved node directly to avoid /bin/sh's DYLD stripping.
//!
//! Network requirement: the deny test requires INTERNET access for DNS
//! resolution of `discord.com`. Tests skip with a clear message on offline
//! CI machines (a one-shot DNS resolution outside the stt-guard wrapper is
//! the prerequisite check; if it fails, we cannot distinguish offline-DNS
//! from Stentorian Guard-deny so the test must skip).

use guard_e2e::{DaemonHarness, cargo_workspace_root, resolve_cli, resolve_dylib, resolve_node};
use std::process::Command;

/// v0.1 deny target: resolves successfully outside Stentorian Guard (real DNS
/// records), NOT in D-18's allowlist. Must NOT be a non-existent host -- that
/// would make Stentorian Guard-deny indistinguishable from NXDOMAIN.
const DENY_HOST: &str = "discord.com";
const DENY_PORT: &str = "443";

/// Pre-test sanity: confirm the deny target actually resolves outside the
/// stt-guard wrapper. If it doesn't (e.g. CI machine has no DNS), we cannot
/// distinguish offline-DNS from Stentorian Guard-deny -- skip the test rather than
/// produce a meaningless pass.
fn deny_target_resolves_outside_guard() -> bool {
    use std::net::ToSocketAddrs;
    format!("{DENY_HOST}:{DENY_PORT}")
        .to_socket_addrs()
        .is_ok_and(|i| i.count() > 0)
}

#[cfg_attr(not(target_os = "macos"), ignore = "macOS-only test")]
#[test]
fn node_connect_to_non_allowlisted_host_is_denied() {
    if !deny_target_resolves_outside_guard() {
        eprintln!(
            "SKIP: {DENY_HOST}:{DENY_PORT} did not resolve outside Stentorian Guard -- cannot \
                   discriminate Stentorian Guard-deny from offline-DNS (sanity gate)"
        );
        return;
    }

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
    let script = cargo_workspace_root().join("crates/guard-e2e/harness/connect_evil.js");
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

    // Roadmap criterion #2: the wrapped command must exit non-zero.
    assert!(
        !output.status.success(),
        "Roadmap #2 violation: wrapped node exited 0 (connect succeeded?)\n\
         host: {DENY_HOST}:{DENY_PORT}\n\
         stdout: {stdout}\n\
         stderr: {stderr}"
    );

    // Our harness script exits 2 when sock.on('error') fires. Any other
    // non-zero code means something else went wrong (timeout, crash).
    assert_eq!(
        output.status.code(),
        Some(2),
        "expected node script's deliberate deny-exit (code 2); got {:?}\n\
         stdout: {stdout}\n\
         stderr: {stderr}",
        output.status.code()
    );

    assert!(
        stdout.contains("CONNECT-FAILED"),
        "expected CONNECT-FAILED in script stdout; got: {stdout}"
    );

    // CRITICAL ASSERTION:
    // - Stentorian Guard-deny at libc connect: errno = EHOSTUNREACH (D-10).
    // - Stentorian Guard-deny at getaddrinfo: Node surfaces EAI_FAIL directly
    //   (libuv thread pool path) or as ENOTFOUND (c-ares path).
    // - ECONNREFUSED would mean Stentorian Guard let the connect through to the
    //   network layer -- that's a TEST BUG (and a Stentorian Guard regression).
    // Because DENY_HOST resolves outside Stentorian Guard (we confirmed at gate
    // time), any of these inside Stentorian Guard is unambiguous evidence of
    // Stentorian Guard firing.
    let guard_deny_errno = stdout.contains("EHOSTUNREACH")
        || stdout.contains("ENOTFOUND")
        || stdout.contains("EAI_FAIL");
    assert!(
        guard_deny_errno,
        "expected EHOSTUNREACH (libc deny), ENOTFOUND, or EAI_FAIL (getaddrinfo deny) \
         in script output -- these are Stentorian Guard's deny errnos for a host that DOES \
         resolve outside Stentorian Guard. Got: {stdout}"
    );

    let test_bug_errno = stdout.contains("ECONNREFUSED");
    assert!(
        !test_bug_errno,
        "ECONNREFUSED means Stentorian Guard let the connect through to the network \
         layer -- Stentorian Guard did NOT enforce. This is either a test bug or a \
         Stentorian Guard regression. Got: {stdout}"
    );
}

#[cfg_attr(not(target_os = "macos"), ignore = "macOS-only test")]
#[test]
fn node_connect_to_loopback_is_denied() {
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
    let inline_script = "const net = require('net'); \
        const s = net.connect(9, '127.0.0.1', () => { console.log('ALLOWED'); s.destroy(); process.exit(5); }); \
        s.on('error', e => { console.log('NETERR', e.code); process.exit(e.code === 'EHOSTUNREACH' ? 0 : 5); }); \
        setTimeout(() => process.exit(3), 5000);";

    let output = Command::new(&cli)
        .arg("wrap")
        .arg(&node)
        .arg("-e")
        .arg(inline_script)
        .env_clear()
        .env("HOME", harness.home.path())
        .env("PATH", std::env::var_os("PATH").unwrap_or_default())
        .env("STT_GUARD_HOOK_DYLIB", &dylib)
        .env("STT_GUARD_STATE_DIR", &harness.state_dir)
        .output()
        .expect("run stt-guard");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(
        output.status.success(),
        "loopback connect must be denied by Stentorian Guard; status={:?}\n\
         stdout: {stdout}\n\
         stderr: {stderr}",
        output.status
    );
    assert!(
        stdout.contains("EHOSTUNREACH"),
        "expected EHOSTUNREACH in stdout; got: {stdout}"
    );
}
