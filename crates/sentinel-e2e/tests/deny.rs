//! Roadmap success criterion #2: a wrapped Node attempt to connect to a
//! non-allowlisted host is BLOCKED by the dylib (intercepted at
//! connect()/getaddrinfo() against the hand-coded allowlist) and the
//! wrapped command exits non-zero.
//!
//! DIFFERENTIAL ASSERTION:
//! The original test against `evil.example.com` could not distinguish
//! Sentinel-deny from offline-DNS-NXDOMAIN: any real resolver returns
//! NXDOMAIN for that subdomain, surfacing in Node as ENOTFOUND -- exactly
//! the same error code the test was accepting as proof of Sentinel-deny.
//! The remediation uses the strongest evidence pattern (differential):
//!
//!   - `node_connect_to_non_allowlisted_host_is_denied`: connects to
//!     `discord.com:443`. discord.com resolves successfully outside
//!     Sentinel (real A records). NOT in D-18's v0.1 allowlist. The
//!     ONLY failure path is Sentinel-induced. We assert the connect-time
//!     errno class is one of Sentinel's deny errnos (EHOSTUNREACH from
//!     libc connect deny, EAI_FAIL from getaddrinfo deny -- surfaced by
//!     Node as ENOTFOUND for the EAI_FAIL path or EHOSTUNREACH for the
//!     connect path). NXDOMAIN cannot happen for a resolvable host so
//!     ENOTFOUND in this test is unambiguous evidence of Sentinel firing
//!     at the getaddrinfo layer.
//!
//!   - `node_connect_to_loopback_is_allowed`: connects to `127.0.0.1:9`.
//!     Loopback IS in D-18's allowlist. ECONNREFUSED proves the connect
//!     reached libc and was refused by the kernel (port 9 not listening)
//!     -- Sentinel did NOT block. The differential vs the deny case proves
//!     Sentinel discriminated based on allowlist membership, not on
//!     "everything fails".
//!
//! Target binary requirement: node must be NON-hardened-runtime (Pitfall 2;
//! spike A2). On macOS 26.x with Homebrew node, this is the case;
//! /usr/bin/python3 and Apple-shipped /bin/sh strip DYLD_*. The tests
//! invoke the resolved node directly to avoid /bin/sh's DYLD stripping.
//!
//! Network requirement: the deny test requires INTERNET access for DNS
//! resolution of `discord.com`. Tests skip with a clear message on offline
//! CI machines (a one-shot DNS resolution outside the sentinel wrapper is
//! the prerequisite check; if it fails, we cannot distinguish offline-DNS
//! from Sentinel-deny so the test must skip).

use sentinel_e2e::{cargo_workspace_root, resolve_cli, resolve_dylib, resolve_node, DaemonHarness};
use std::process::Command;

/// v0.1 deny target: resolves successfully outside Sentinel (real DNS
/// records), NOT in D-18's allowlist. Must NOT be a non-existent host -- that
/// would make Sentinel-deny indistinguishable from NXDOMAIN.
const DENY_HOST: &str = "discord.com";
const DENY_PORT: &str = "443";

/// Pre-test sanity: confirm the deny target actually resolves outside the
/// sentinel wrapper. If it doesn't (e.g. CI machine has no DNS), we cannot
/// distinguish offline-DNS from Sentinel-deny -- skip the test rather than
/// produce a meaningless pass.
fn deny_target_resolves_outside_sentinel() -> bool {
    use std::net::ToSocketAddrs;
    format!("{}:{}", DENY_HOST, DENY_PORT)
        .to_socket_addrs()
        .map(|i| i.count() > 0)
        .unwrap_or(false)
}

#[cfg_attr(not(target_os = "macos"), ignore)]
#[test]
fn node_connect_to_non_allowlisted_host_is_denied() {
    if !deny_target_resolves_outside_sentinel() {
        eprintln!(
            "SKIP: {}:{} did not resolve outside Sentinel -- cannot \
                   discriminate Sentinel-deny from offline-DNS (sanity gate)",
            DENY_HOST, DENY_PORT
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
    let script = cargo_workspace_root().join("crates/sentinel-e2e/harness/connect_evil.js");
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
        .env("SENTINEL_HOOK_DYLIB", &dylib)
        .env("SENTINEL_STATE_DIR", &harness.state_dir)
        .env("SENTINEL_DENY_HOST", DENY_HOST)
        .env("SENTINEL_DENY_PORT", DENY_PORT)
        .output()
        .expect("run sentinel");

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
    // - Sentinel-deny at libc connect: errno = EHOSTUNREACH (D-10).
    // - Sentinel-deny at getaddrinfo: errno = EAI_FAIL (D-10) -- Node's
    //   dns layer surfaces this as ENOTFOUND (because EAI_FAIL is
    //   c-ares's "non-recoverable failure" path, mapped to ENOTFOUND).
    // - ECONNREFUSED would mean Sentinel let the connect through to the
    //   network layer -- that's a TEST BUG (and a Sentinel regression).
    // Because DENY_HOST resolves outside Sentinel (we confirmed at gate
    // time), ENOTFOUND inside Sentinel is unambiguous evidence of
    // Sentinel firing at the getaddrinfo layer.
    let sentinel_deny_errno =
        stdout.contains("EHOSTUNREACH") || stdout.contains("ENOTFOUND");
    assert!(
        sentinel_deny_errno,
        "expected EHOSTUNREACH (libc deny) or ENOTFOUND (getaddrinfo deny) in script \
         output -- these are Sentinel's deny errnos for a host that DOES resolve \
         outside Sentinel. Got: {stdout}"
    );

    let test_bug_errno = stdout.contains("ECONNREFUSED");
    assert!(
        !test_bug_errno,
        "ECONNREFUSED means Sentinel let the connect through to the network \
         layer -- Sentinel did NOT enforce. This is either a test bug or a \
         Sentinel regression. Got: {stdout}"
    );
}

#[cfg_attr(not(target_os = "macos"), ignore)]
#[test]
fn node_connect_to_loopback_is_allowed() {
    // Differential companion: 127.0.0.1 IS in the v0.1 allowlist
    // (D-18). A Node connect to 127.0.0.1:9 (discard service) should NOT be
    // blocked by Sentinel; it'll fail with ECONNREFUSED (no service
    // listening on port 9) -- which is a NETWORK-level failure, NOT Sentinel
    // deny. The ECONNREFUSED-vs-EHOSTUNREACH distinction proves the verdict
    // path chose Allow for the loopback case while choosing Deny for the
    // non-allowlisted case in the deny test above.
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
        const s = net.connect(9, '127.0.0.1', () => { console.log('ALLOWED'); s.destroy(); process.exit(0); }); \
        s.on('error', e => { console.log('NETERR', e.code); process.exit(e.code === 'ECONNREFUSED' ? 0 : 5); }); \
        setTimeout(() => process.exit(3), 5000);";

    let output = Command::new(&cli)
        .arg("wrap")
        .arg(&node)
        .arg("-e")
        .arg(inline_script)
        .env_clear()
        .env("HOME", harness.home.path())
        .env("PATH", std::env::var_os("PATH").unwrap_or_default())
        .env("SENTINEL_HOOK_DYLIB", &dylib)
        .env("SENTINEL_STATE_DIR", &harness.state_dir)
        .output()
        .expect("run sentinel");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    // Allow path: either ALLOWED (something is listening) or NETERR ECONNREFUSED
    // (allowlist passed; network said no). Both are exit 0 in our script.
    assert!(
        output.status.success(),
        "loopback connect must reach the network layer (ECONNREFUSED is OK); status={:?}\n\
         stdout: {stdout}\n\
         stderr: {stderr}",
        output.status
    );
    assert!(
        stdout.contains("ECONNREFUSED") || stdout.contains("ALLOWED"),
        "expected ECONNREFUSED or ALLOWED in stdout (proves the connect went to libc, \
         not denied by Sentinel); got: {stdout}"
    );

    // EHOSTUNREACH would mean Sentinel denied the loopback case -- that's a
    // critical bug (D-18 explicitly allowlists loopback).
    assert!(
        !stdout.contains("EHOSTUNREACH"),
        "Sentinel denied loopback! D-18 says 127.0.0.1 IS in the v0.1 \
         allowlist; this is a critical regression. Got: {stdout}"
    );
}
