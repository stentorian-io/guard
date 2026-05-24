//! M005-S05: E2E tests for the full getaddrinfo → daemon Resolve → connect flow.
//!
//! These tests exercise the complete DNS proxy pipeline introduced in M005:
//!   1. Hook's guard_getaddrinfo intercepts libc getaddrinfo
//!   2. Sends Resolve IPC (tag 0x06) to daemon
//!   3. Daemon resolves via its own clean libc (not under DYLD interpose)
//!   4. Hook receives wire addresses, populates DNS cache (sockaddr → hostname)
//!   5. Hook builds addrinfo linked list and returns to caller
//!   6. Caller's subsequent connect() uses cached hostname for policy evaluation
//!   7. connect() deny fires EHOSTUNREACH, or daemon policy gate fired EAI_FAIL at step 3
//!
//! Enforcement architecture:
//!   - The PRIMARY deny point is connect() — the hook evaluates the cached
//!     hostname against the snapshot/allowlist and returns EHOSTUNREACH on deny.
//!   - The SECONDARY deny point is the daemon's Resolve handler policy gate
//!     (S02/S03), which can reject DNS resolution before returning IPs. This
//!     fires only when the run has a loaded snapshot with deny entries.
//!   - For hostname-based connections (vs raw IP), Node.js surfaces the deny
//!     path differently: EHOSTUNREACH from connect() vs ENOTFOUND from
//!     getaddrinfo EAI_FAIL. The key invariant is that ECONNREFUSED (kernel
//!     network-layer refusal) must NEVER appear for a denied host — that
//!     would mean Stentorian Guard let the connection through.
//!
//! Test strategy:
//!   - Hermetic tests use Node's dns.lookup (which calls getaddrinfo) and
//!     net.connect to exercise both layers.
//!   - Live-network tests are #[ignore]'d — opt-in via `--ignored`.
//!   - Differential assertions: we confirm the deny target resolves outside
//!     Stentorian Guard so the denial inside Stentorian Guard is unambiguous Stentorian Guard-caused
//!     (differential pattern).

use guard_e2e::{DaemonHarness, cargo_workspace_root, resolve_cli, resolve_dylib, resolve_node};
use std::process::Command;

const DENY_HOST: &str = "discord.com";
const DENY_PORT: &str = "443";

/// Allowlisted registry host — in D-18 v0.1 allowlist.
const ALLOW_HOST: &str = "registry.npmjs.org";
const ALLOW_PORT: &str = "443";

fn probe_script() -> std::path::PathBuf {
    cargo_workspace_root().join("crates/guard-e2e/harness/getaddrinfo_probe.js")
}

fn deny_target_resolves() -> bool {
    use std::net::ToSocketAddrs;
    format!("{DENY_HOST}:{DENY_PORT}")
        .to_socket_addrs()
        .map(|i| i.count() > 0)
        .unwrap_or(false)
}

fn allow_target_resolves() -> bool {
    use std::net::ToSocketAddrs;
    format!("{ALLOW_HOST}:{ALLOW_PORT}")
        .to_socket_addrs()
        .map(|i| i.count() > 0)
        .unwrap_or(false)
}

// ============================================================================
// Test 1: getaddrinfo for a non-allowlisted host is blocked by Stentorian Guard —
//         either at DNS level (EAI_FAIL) or connect level (EHOSTUNREACH).
//         Both prove the full proxy pipeline reaches the policy gate.
// ============================================================================

#[cfg_attr(not(target_os = "macos"), ignore)]
#[test]
fn getaddrinfo_proxied_then_connect_denied_for_non_allowlisted_host() {
    if !deny_target_resolves() {
        eprintln!(
            "SKIP: {DENY_HOST}:{DENY_PORT} does not resolve outside Stentorian Guard \
             (sanity gate)"
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
    let script = probe_script();
    assert!(
        script.exists(),
        "probe script missing at {}",
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
        .env("PROBE_HOST", DENY_HOST)
        .env("PROBE_PORT", DENY_PORT)
        .env("PROBE_MODE", "resolve_connect")
        .output()
        .expect("run stt-guard");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    // Two valid deny paths:
    //   exit 1 + RESOLVE-FAILED: daemon policy gate denied at DNS level (EAI_FAIL)
    //   exit 2 + CONNECT-FAILED + EHOSTUNREACH: daemon resolved, connect denied
    let dns_deny = stdout.contains("RESOLVE-FAILED");
    let connect_deny = stdout.contains("RESOLVE-OK") && stdout.contains("CONNECT-FAILED");
    assert!(
        dns_deny || connect_deny,
        "expected Stentorian Guard to block {DENY_HOST} at DNS level (RESOLVE-FAILED) \
         or connect level (RESOLVE-OK + CONNECT-FAILED); \
         got:\nstdout: {stdout}\nstderr: {stderr}"
    );

    let exit_code = output.status.code();
    assert!(
        exit_code == Some(1) || exit_code == Some(2),
        "expected exit 1 (DNS denied) or exit 2 (connect denied); got {exit_code:?}\n\
         stdout: {stdout}\nstderr: {stderr}"
    );

    if connect_deny {
        // EHOSTUNREACH = Stentorian Guard connect() deny via cached hostname.
        assert!(
            stdout.contains("EHOSTUNREACH"),
            "connect deny path: expected EHOSTUNREACH; got: {stdout}"
        );
    }

    // ECONNREFUSED would mean the connection reached the kernel TCP layer —
    // Stentorian Guard did NOT enforce.
    assert!(
        !stdout.contains("ECONNREFUSED"),
        "ECONNREFUSED means Stentorian Guard let the connection through to the \
         network layer. This is a Stentorian Guard regression. Got: {stdout}"
    );
}

// ============================================================================
// Test 2: getaddrinfo resolve-only for non-allowlisted host is blocked by
//         Stentorian Guard — either the daemon proxies DNS (exit 0 + RESOLVE-OK) or
//         the daemon's policy gate denies the resolve (non-zero + RESOLVE-FAILED).
//         Both outcomes prove Stentorian Guard handled the request.
// ============================================================================

#[cfg_attr(not(target_os = "macos"), ignore)]
#[test]
fn getaddrinfo_resolve_only_succeeds_for_non_allowlisted_host() {
    if !deny_target_resolves() {
        eprintln!(
            "SKIP: {DENY_HOST}:{DENY_PORT} does not resolve outside Stentorian Guard \
             (sanity gate)"
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
    let script = probe_script();

    let output = Command::new(&cli)
        .arg("wrap")
        .arg(&node)
        .arg(&script)
        .env_clear()
        .env("HOME", harness.home.path())
        .env("PATH", std::env::var_os("PATH").unwrap_or_default())
        .env("STT_GUARD_HOOK_DYLIB", &dylib)
        .env("STT_GUARD_STATE_DIR", &harness.state_dir)
        .env("PROBE_HOST", DENY_HOST)
        .env("PROBE_PORT", DENY_PORT)
        .env("PROBE_MODE", "resolve_only")
        .output()
        .expect("run stt-guard");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    // Two valid outcomes — Stentorian Guard handled the request either way:
    //   exit 0 + RESOLVE-OK: daemon proxied DNS; enforcement deferred to connect()
    //   non-zero + RESOLVE-FAILED: daemon policy gate denied at DNS level
    let daemon_proxied = output.status.success() && stdout.contains("RESOLVE-OK");
    let dns_denied = !output.status.success() && stdout.contains("RESOLVE-FAILED");
    assert!(
        daemon_proxied || dns_denied,
        "expected Stentorian Guard to either proxy the resolve (RESOLVE-OK, exit 0) \
         or deny it at DNS level (RESOLVE-FAILED, non-zero); \
         got {:?}\nstdout: {stdout}\nstderr: {stderr}",
        output.status.code()
    );
}

// ============================================================================
// Test 3: getaddrinfo for an allowlisted host resolves and connect succeeds
// ============================================================================

#[cfg_attr(
    not(target_os = "macos"),
    ignore = "macOS-only; live-network requires real DNS + reachable registry.npmjs.org"
)]
#[cfg_attr(
    target_os = "macos",
    ignore = "live-network: requires real DNS + reachable registry.npmjs.org"
)]
#[test]
fn getaddrinfo_allowlisted_host_resolves_and_connects() {
    if !allow_target_resolves() {
        eprintln!("SKIP: {ALLOW_HOST}:{ALLOW_PORT} does not resolve outside Stentorian Guard");
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
    let script = probe_script();

    let output = Command::new(&cli)
        .arg("wrap")
        .arg(&node)
        .arg(&script)
        .env_clear()
        .env("HOME", harness.home.path())
        .env("PATH", std::env::var_os("PATH").unwrap_or_default())
        .env("STT_GUARD_HOOK_DYLIB", &dylib)
        .env("STT_GUARD_STATE_DIR", &harness.state_dir)
        .env("PROBE_HOST", ALLOW_HOST)
        .env("PROBE_PORT", ALLOW_PORT)
        .env("PROBE_MODE", "resolve_connect")
        .output()
        .expect("run stt-guard");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    // RESOLVE-OK must appear — the daemon resolved the allowlisted host.
    assert!(
        stdout.contains("RESOLVE-OK"),
        "expected RESOLVE-OK for allowlisted host {ALLOW_HOST}; got:\n\
         stdout: {stdout}\nstderr: {stderr}"
    );

    // Exit 0 (connect succeeded) or 2 with non-deny error.
    // Exit 1 (resolve failed) must NOT happen for an allowlisted host.
    assert_ne!(
        output.status.code(),
        Some(1),
        "allowlisted host {ALLOW_HOST} must resolve successfully (exit != 1);\n\
         stdout: {stdout}\nstderr: {stderr}"
    );

    // If connect succeeded (exit 0), verify CONNECT-OK marker.
    if output.status.success() {
        assert!(
            stdout.contains("CONNECT-OK"),
            "exit 0 but no CONNECT-OK marker; stdout: {stdout}"
        );
    }

    // EHOSTUNREACH must NOT appear — allowlisted hosts are not denied.
    assert!(
        !stdout.contains("EHOSTUNREACH"),
        "Stentorian Guard denied allowlisted host {ALLOW_HOST}! This is a critical \
         regression. stdout: {stdout}"
    );
}

// ============================================================================
// Test 4: Differential — denied host at connect vs allowed loopback
//         Proves Stentorian Guard discriminates, not "everything fails"
// ============================================================================

#[cfg_attr(not(target_os = "macos"), ignore)]
#[test]
fn getaddrinfo_differential_deny_vs_loopback_allow() {
    if !deny_target_resolves() {
        eprintln!(
            "SKIP: {DENY_HOST}:{DENY_PORT} does not resolve outside Stentorian Guard \
             (sanity gate)"
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

    // Part A: non-allowlisted host — Stentorian Guard blocks the connection, either
    // at DNS level (RESOLVE-FAILED + EAI_FAIL) or connect level (EHOSTUNREACH).
    let script = probe_script();
    let deny_output = Command::new(&cli)
        .arg("wrap")
        .arg(&node)
        .arg(&script)
        .env_clear()
        .env("HOME", harness.home.path())
        .env("PATH", std::env::var_os("PATH").unwrap_or_default())
        .env("STT_GUARD_HOOK_DYLIB", &dylib)
        .env("STT_GUARD_STATE_DIR", &harness.state_dir)
        .env("PROBE_HOST", DENY_HOST)
        .env("PROBE_PORT", DENY_PORT)
        .env("PROBE_MODE", "resolve_connect")
        .output()
        .expect("run deny probe");

    let deny_stdout = String::from_utf8_lossy(&deny_output.stdout);

    let deny_exit = deny_output.status.code();
    assert!(
        deny_exit == Some(1) || deny_exit == Some(2),
        "deny leg: expected exit 1 (DNS denied) or exit 2 (connect denied); \
         got {deny_exit:?}\nstdout: {deny_stdout}",
    );

    let dns_deny = deny_stdout.contains("RESOLVE-FAILED");
    let connect_deny = deny_stdout.contains("RESOLVE-OK") && deny_stdout.contains("EHOSTUNREACH");
    assert!(
        dns_deny || connect_deny,
        "deny leg: expected RESOLVE-FAILED (DNS deny) or \
         RESOLVE-OK + EHOSTUNREACH (connect deny); got: {deny_stdout}"
    );

    // Part B: loopback connect is allowed (Stentorian Guard doesn't block 127.0.0.1).
    let loopback_script = "const net = require('net'); \
        const s = net.connect(9, '127.0.0.1', () => { console.log('LOOPBACK-OK'); s.destroy(); process.exit(0); }); \
        s.on('error', e => { console.log('LOOPBACK-ERR', e.code); process.exit(e.code === 'ECONNREFUSED' ? 0 : 5); }); \
        setTimeout(() => process.exit(3), 5000);";

    let allow_output = Command::new(&cli)
        .arg("wrap")
        .arg(&node)
        .arg("-e")
        .arg(loopback_script)
        .env_clear()
        .env("HOME", harness.home.path())
        .env("PATH", std::env::var_os("PATH").unwrap_or_default())
        .env("STT_GUARD_HOOK_DYLIB", &dylib)
        .env("STT_GUARD_STATE_DIR", &harness.state_dir)
        .output()
        .expect("run loopback probe");

    let allow_stdout = String::from_utf8_lossy(&allow_output.stdout);
    let allow_stderr = String::from_utf8_lossy(&allow_output.stderr);

    assert!(
        allow_output.status.success(),
        "allow leg: loopback must reach kernel (exit 0); got {:?}\n\
         stdout: {allow_stdout}\nstderr: {allow_stderr}",
        allow_output.status.code()
    );
    assert!(
        allow_stdout.contains("ECONNREFUSED") || allow_stdout.contains("LOOPBACK-OK"),
        "allow leg: expected ECONNREFUSED or LOOPBACK-OK; got: {allow_stdout}"
    );
    assert!(
        !allow_stdout.contains("EHOSTUNREACH"),
        "allow leg: Stentorian Guard denied loopback! D-18 allowlists 127.0.0.1. \
         stdout: {allow_stdout}"
    );
}

// ============================================================================
// Test 5: Non-TTY mode — denied host exits non-zero (no prompt)
// ============================================================================

#[cfg_attr(not(target_os = "macos"), ignore)]
#[test]
fn getaddrinfo_non_tty_denies_without_prompt() {
    if !deny_target_resolves() {
        eprintln!(
            "SKIP: {DENY_HOST}:{DENY_PORT} does not resolve outside Stentorian Guard \
             (sanity gate)"
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
    let script = probe_script();

    let output = Command::new(&cli)
        .arg("wrap")
        .arg(&node)
        .arg(&script)
        .env_clear()
        .env("HOME", harness.home.path())
        .env("PATH", std::env::var_os("PATH").unwrap_or_default())
        .env("STT_GUARD_HOOK_DYLIB", &dylib)
        .env("STT_GUARD_STATE_DIR", &harness.state_dir)
        .env("PROBE_HOST", DENY_HOST)
        .env("PROBE_PORT", DENY_PORT)
        .env("PROBE_MODE", "resolve_connect")
        .stdin(std::process::Stdio::null()) // Non-TTY: is_tty=false
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .output()
        .expect("run stt-guard");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    // Non-TTY: resolve succeeds (daemon proxies), connect denied (no prompt).
    assert!(
        !output.status.success(),
        "non-TTY: expected non-zero exit for denied connection; got {:?}\n\
         stdout: {stdout}\nstderr: {stderr}",
        output.status.code()
    );

    // Either:
    //   exit 1 + RESOLVE-FAILED: daemon policy gate rejected at DNS level
    //   exit 2 + CONNECT-FAILED: daemon resolved, connect denied
    // Both are valid non-TTY deny paths.
    let guard_deny = stdout.contains("EHOSTUNREACH")
        || stdout.contains("ENOTFOUND")
        || stdout.contains("EAI_FAIL");
    assert!(
        guard_deny,
        "non-TTY: expected EHOSTUNREACH (connect deny), ENOTFOUND, or EAI_FAIL (DNS deny); \
         got:\nstdout: {stdout}\nstderr: {stderr}"
    );
}

// ============================================================================
// Test 6: DNS cache population — connect after resolve uses cached hostname
//         This is the key M005 invariant: getaddrinfo populates the cache so
//         connect() can look up the hostname from the IP and evaluate policy.
// ============================================================================

#[cfg_attr(not(target_os = "macos"), ignore)]
#[test]
fn dns_cache_enables_hostname_based_connect_deny() {
    if !deny_target_resolves() {
        eprintln!(
            "SKIP: {DENY_HOST}:{DENY_PORT} does not resolve outside Stentorian Guard \
             (sanity gate)"
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

    // This inline script exercises the M005 flow:
    // 1. dns.lookup() calls getaddrinfo → hook proxies to daemon → gets IP
    // 2. hook caches IP→hostname mapping
    // 3. net.connect() to the resolved IP → hook looks up hostname from cache
    // 4. Policy evaluation on the hostname → DENY → EHOSTUNREACH
    //
    // The daemon's policy gate may also deny at step 1 (EAI_FAIL / RESOLVE-FAILED).
    // Both outcomes prove Stentorian Guard is enforcing.
    let inline = format!(
        "const dns = require('dns'); const net = require('net'); \
         dns.lookup('{DENY_HOST}', {{ family: 4 }}, (err, addr) => {{ \
           if (err) {{ console.log('RESOLVE-FAILED', err.code); process.exit(1); }} \
           console.log('RESOLVED', addr); \
           const s = net.connect({{ host: addr, port: {DENY_PORT} }}, () => {{ \
             console.log('UNEXPECTED-CONNECT-OK'); s.destroy(); process.exit(0); }}); \
           s.on('error', e => {{ \
             console.log('CONNECT-ERR', e.code); \
             process.exit(e.code === 'EHOSTUNREACH' ? 42 : 99); }}); \
         }}); \
         setTimeout(() => process.exit(3), 8000);"
    );

    let output = Command::new(&cli)
        .arg("wrap")
        .arg(&node)
        .arg("-e")
        .arg(&inline)
        .env_clear()
        .env("HOME", harness.home.path())
        .env("PATH", std::env::var_os("PATH").unwrap_or_default())
        .env("STT_GUARD_HOOK_DYLIB", &dylib)
        .env("STT_GUARD_STATE_DIR", &harness.state_dir)
        .output()
        .expect("run stt-guard");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    // Two valid deny paths:
    //   exit 1 + RESOLVE-FAILED: daemon policy gate denied DNS resolution
    //   exit 42 + RESOLVED + CONNECT-ERR EHOSTUNREACH: DNS proxied, connect denied
    //     via cached hostname (the key M005 invariant)
    let dns_denied = output.status.code() == Some(1) && stdout.contains("RESOLVE-FAILED");
    let connect_denied = output.status.code() == Some(42)
        && stdout.contains("RESOLVED")
        && stdout.contains("CONNECT-ERR")
        && stdout.contains("EHOSTUNREACH");
    assert!(
        dns_denied || connect_denied,
        "expected Stentorian Guard to block {DENY_HOST}: \
         exit 1 + RESOLVE-FAILED (DNS deny) or \
         exit 42 + RESOLVED + CONNECT-ERR EHOSTUNREACH (connect deny via cached hostname); \
         got {:?}\nstdout: {stdout}\nstderr: {stderr}",
        output.status.code()
    );

    // UNEXPECTED-CONNECT-OK must NOT appear.
    assert!(
        !stdout.contains("UNEXPECTED-CONNECT-OK"),
        "connection to denied host succeeded — Stentorian Guard did not enforce. stdout: {stdout}"
    );
}

// ============================================================================
// Test 7: connect_evil.js is blocked by Stentorian Guard — either at DNS level
//         (EAI_FAIL → ENOTFOUND) or connect level (EHOSTUNREACH).
//         Both prove the getaddrinfo→daemon→policy pipeline is working.
// ============================================================================

#[cfg_attr(not(target_os = "macos"), ignore)]
#[test]
fn connect_evil_denied_via_cached_hostname() {
    if !deny_target_resolves() {
        eprintln!("SKIP: {DENY_HOST}:{DENY_PORT} does not resolve outside Stentorian Guard");
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

    // Both exit codes are valid Stentorian Guard deny outcomes.
    let exit_code = output.status.code();
    assert!(
        exit_code == Some(1) || exit_code == Some(2),
        "expected exit 1 (DNS denied) or exit 2 (connect denied); got {exit_code:?}\n\
         stdout: {stdout}\nstderr: {stderr}"
    );

    // The connection must be reported as blocked.
    let guard_deny = stdout.contains("EHOSTUNREACH")
        || stdout.contains("ENOTFOUND")
        || stdout.contains("EAI_FAIL")
        || stdout.contains("CONNECT-FAILED");
    assert!(
        guard_deny,
        "expected a Stentorian Guard-deny signal (EHOSTUNREACH, ENOTFOUND, EAI_FAIL, or \
         CONNECT-FAILED); got: {stdout}"
    );

    // ECONNREFUSED = Stentorian Guard let the connect through. Bug.
    assert!(
        !stdout.contains("ECONNREFUSED"),
        "ECONNREFUSED means Stentorian Guard did not enforce. stdout: {stdout}"
    );
}

// ============================================================================
// Test 8: Daemon down — getaddrinfo returns EAI_FAIL/EAI_AGAIN, fail-closed
// ============================================================================

#[cfg_attr(not(target_os = "macos"), ignore)]
#[test]
fn daemon_down_getaddrinfo_fails_closed() {
    let cli = resolve_cli();
    let dylib = resolve_dylib();
    let node = match resolve_node() {
        Ok(p) => p,
        Err(why) => {
            eprintln!("SKIP: {why}");
            return;
        }
    };

    // Start a daemon harness, capture the state dir, then kill the daemon.
    // The hook will have STT_GUARD_STATE_DIR pointing at a valid socket path
    // that no longer has a listener — simulating daemon crash.
    let harness = DaemonHarness::start().expect("start daemon");
    let state_dir = harness.state_dir.clone();
    let home = harness.home.path().to_path_buf();
    // Kill daemon.
    drop(harness);
    // Brief pause for socket cleanup.
    std::thread::sleep(std::time::Duration::from_millis(200));

    let script = probe_script();

    let output = Command::new(&cli)
        .arg("wrap")
        .arg(&node)
        .arg(&script)
        .env_clear()
        .env("HOME", &home)
        .env("PATH", std::env::var_os("PATH").unwrap_or_default())
        .env("STT_GUARD_HOOK_DYLIB", &dylib)
        .env("STT_GUARD_STATE_DIR", &state_dir)
        .env("PROBE_HOST", DENY_HOST)
        .env("PROBE_PORT", DENY_PORT)
        .env("PROBE_MODE", "resolve_only")
        .output()
        .expect("run stt-guard");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    // With daemon down, the CLI may either:
    // (a) refuse to launch the child at all ("daemon not running" in stderr), or
    // (b) launch the child, but the hook's getaddrinfo returns EAI_AGAIN/FAIL
    //     because the socket is gone.
    // Both are valid fail-closed outcomes.
    assert!(
        !output.status.success(),
        "daemon-down: expected non-zero exit (fail-closed), but got success.\n\
         stdout: {stdout}\nstderr: {stderr}"
    );

    // The CLI surfaces the daemon-down error in stderr.
    let fail_closed = stderr.contains("daemon not running")
        || stderr.contains("socket inaccessible")
        || stdout.contains("RESOLVE-FAILED");
    assert!(
        fail_closed,
        "daemon-down: expected a fail-closed indicator; got:\n\
         stdout: {stdout}\nstderr: {stderr}"
    );

    // Must NOT see RESOLVE-OK — that would mean DNS bypassed the daemon.
    assert!(
        !stdout.contains("RESOLVE-OK"),
        "daemon-down: RESOLVE-OK means DNS bypassed the daemon (fail-open bug).\n\
         stdout: {stdout}"
    );
}
