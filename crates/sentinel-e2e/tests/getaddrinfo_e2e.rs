//! M005-S05: E2E tests for the full getaddrinfo → daemon Resolve → connect flow.
//!
//! These tests exercise the complete DNS proxy pipeline introduced in M005:
//!   1. Hook's sentinel_getaddrinfo intercepts libc getaddrinfo
//!   2. Sends Resolve IPC (tag 0x06) to daemon
//!   3. Daemon resolves via its own clean libc (not under DYLD interpose)
//!   4. Hook receives wire addresses, populates DNS cache (sockaddr → hostname)
//!   5. Hook builds addrinfo linked list and returns to caller
//!   6. Caller's subsequent connect() uses cached hostname for policy evaluation
//!   7. connect() deny fires EHOSTUNREACH for non-allowlisted hosts
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
//!     would mean Sentinel let the connection through.
//!
//! Test strategy:
//!   - Hermetic tests use Node's dns.lookup (which calls getaddrinfo) and
//!     net.connect to exercise both layers.
//!   - Live-network tests are #[ignore]'d — opt-in via `--ignored`.
//!   - Differential assertions: we confirm the deny target resolves outside
//!     Sentinel so the denial inside Sentinel is unambiguous Sentinel-caused
//!     (ISS-03 pattern).

use sentinel_e2e::{cargo_workspace_root, resolve_cli, resolve_dylib, resolve_node, DaemonHarness};
use std::process::Command;

const DENY_HOST: &str = "discord.com";
const DENY_PORT: &str = "443";

/// Allowlisted registry host — in D-18 Phase 1 allowlist.
const ALLOW_HOST: &str = "registry.npmjs.org";
const ALLOW_PORT: &str = "443";

fn probe_script() -> std::path::PathBuf {
    cargo_workspace_root().join("crates/sentinel-e2e/harness/getaddrinfo_probe.js")
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
// Test 1: getaddrinfo for a non-allowlisted host resolves via daemon, then
//         connect is denied — proves the full proxy pipeline works
// ============================================================================

#[cfg_attr(not(target_os = "macos"), ignore)]
#[test]
fn getaddrinfo_proxied_then_connect_denied_for_non_allowlisted_host() {
    if !deny_target_resolves() {
        eprintln!(
            "SKIP: {DENY_HOST}:{DENY_PORT} does not resolve outside Sentinel \
             (ISS-03 sanity gate)"
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
    assert!(script.exists(), "probe script missing at {}", script.display());

    let output = Command::new(&cli)
        .arg(&node)
        .arg(&script)
        .env_clear()
        .env("HOME", harness.home.path())
        .env("PATH", std::env::var_os("PATH").unwrap_or_default())
        .env("SENTINEL_HOOK_DYLIB", &dylib)
        .env("SENTINEL_STATE_DIR", &harness.state_dir)
        .env("PROBE_HOST", DENY_HOST)
        .env("PROBE_PORT", DENY_PORT)
        .env("PROBE_MODE", "resolve_connect")
        .output()
        .expect("run sentinel");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    // The daemon proxies the DNS resolution (RESOLVE-OK), then the hook
    // denies at connect() using the cached hostname.
    assert!(
        stdout.contains("RESOLVE-OK"),
        "getaddrinfo must proxy through daemon and resolve successfully; \
         got:\nstdout: {stdout}\nstderr: {stderr}"
    );

    // Exit 2 = resolve succeeded but connect failed.
    assert_eq!(
        output.status.code(),
        Some(2),
        "expected exit 2 (resolve OK, connect denied); got {:?}\n\
         stdout: {stdout}\nstderr: {stderr}",
        output.status.code()
    );

    assert!(
        stdout.contains("CONNECT-FAILED"),
        "expected CONNECT-FAILED after resolved IP is denied; got: {stdout}"
    );

    // EHOSTUNREACH = Sentinel connect() deny. This is the correct deny path
    // for a hostname that resolved via daemon but is not in the allowlist.
    assert!(
        stdout.contains("EHOSTUNREACH"),
        "expected EHOSTUNREACH (Sentinel connect deny) — the daemon resolved \
         the hostname, cached the mapping, and connect() denied via the cached \
         hostname policy check; got: {stdout}"
    );

    // ECONNREFUSED would mean the connection reached the kernel TCP layer —
    // Sentinel did NOT enforce.
    assert!(
        !stdout.contains("ECONNREFUSED"),
        "ECONNREFUSED means Sentinel let the connection through to the \
         network layer. This is a Sentinel regression. Got: {stdout}"
    );
}

// ============================================================================
// Test 2: getaddrinfo resolve-only for non-allowlisted host succeeds
//         (DNS resolution itself is not blocked; enforcement is at connect)
// ============================================================================

#[cfg_attr(not(target_os = "macos"), ignore)]
#[test]
fn getaddrinfo_resolve_only_succeeds_for_non_allowlisted_host() {
    if !deny_target_resolves() {
        eprintln!(
            "SKIP: {DENY_HOST}:{DENY_PORT} does not resolve outside Sentinel \
             (ISS-03 sanity gate)"
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
        .arg(&node)
        .arg(&script)
        .env_clear()
        .env("HOME", harness.home.path())
        .env("PATH", std::env::var_os("PATH").unwrap_or_default())
        .env("SENTINEL_HOOK_DYLIB", &dylib)
        .env("SENTINEL_STATE_DIR", &harness.state_dir)
        .env("PROBE_HOST", DENY_HOST)
        .env("PROBE_PORT", DENY_PORT)
        .env("PROBE_MODE", "resolve_only")
        .output()
        .expect("run sentinel");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    // DNS resolution alone succeeds — the daemon proxies it. The deny
    // enforcement fires at connect() time, not at getaddrinfo time.
    assert!(
        output.status.success(),
        "resolve-only for {DENY_HOST} must succeed (enforcement is at connect); \
         got {:?}\nstdout: {stdout}\nstderr: {stderr}",
        output.status.code()
    );

    assert!(
        stdout.contains("RESOLVE-OK"),
        "expected RESOLVE-OK for daemon-proxied resolution; stdout: {stdout}"
    );
}

// ============================================================================
// Test 3: getaddrinfo for an allowlisted host resolves and connect succeeds
// ============================================================================

#[cfg_attr(not(target_os = "macos"), ignore)]
#[ignore = "live-network: requires real DNS + reachable registry.npmjs.org"]
#[test]
fn getaddrinfo_allowlisted_host_resolves_and_connects() {
    if !allow_target_resolves() {
        eprintln!(
            "SKIP: {ALLOW_HOST}:{ALLOW_PORT} does not resolve outside Sentinel"
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
        .arg(&node)
        .arg(&script)
        .env_clear()
        .env("HOME", harness.home.path())
        .env("PATH", std::env::var_os("PATH").unwrap_or_default())
        .env("SENTINEL_HOOK_DYLIB", &dylib)
        .env("SENTINEL_STATE_DIR", &harness.state_dir)
        .env("PROBE_HOST", ALLOW_HOST)
        .env("PROBE_PORT", ALLOW_PORT)
        .env("PROBE_MODE", "resolve_connect")
        .output()
        .expect("run sentinel");

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
        "Sentinel denied allowlisted host {ALLOW_HOST}! This is a critical \
         regression. stdout: {stdout}"
    );
}

// ============================================================================
// Test 4: Differential — denied host at connect vs allowed loopback
//         Proves Sentinel discriminates, not "everything fails"
// ============================================================================

#[cfg_attr(not(target_os = "macos"), ignore)]
#[test]
fn getaddrinfo_differential_deny_vs_loopback_allow() {
    if !deny_target_resolves() {
        eprintln!(
            "SKIP: {DENY_HOST}:{DENY_PORT} does not resolve outside Sentinel \
             (ISS-03 sanity gate)"
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

    // Part A: non-allowlisted host — resolve succeeds, connect denied.
    let script = probe_script();
    let deny_output = Command::new(&cli)
        .arg(&node)
        .arg(&script)
        .env_clear()
        .env("HOME", harness.home.path())
        .env("PATH", std::env::var_os("PATH").unwrap_or_default())
        .env("SENTINEL_HOOK_DYLIB", &dylib)
        .env("SENTINEL_STATE_DIR", &harness.state_dir)
        .env("PROBE_HOST", DENY_HOST)
        .env("PROBE_PORT", DENY_PORT)
        .env("PROBE_MODE", "resolve_connect")
        .output()
        .expect("run deny probe");

    let deny_stdout = String::from_utf8_lossy(&deny_output.stdout);

    assert_eq!(
        deny_output.status.code(),
        Some(2),
        "deny leg: expected exit 2 (resolve OK, connect denied); got {:?}\n\
         stdout: {deny_stdout}",
        deny_output.status.code()
    );
    assert!(
        deny_stdout.contains("RESOLVE-OK"),
        "deny leg: expected RESOLVE-OK (daemon proxied DNS); got: {deny_stdout}"
    );
    assert!(
        deny_stdout.contains("EHOSTUNREACH"),
        "deny leg: expected EHOSTUNREACH (connect deny); got: {deny_stdout}"
    );

    // Part B: loopback connect is allowed (Sentinel doesn't block 127.0.0.1).
    let loopback_script = "const net = require('net'); \
        const s = net.connect(9, '127.0.0.1', () => { console.log('LOOPBACK-OK'); s.destroy(); process.exit(0); }); \
        s.on('error', e => { console.log('LOOPBACK-ERR', e.code); process.exit(e.code === 'ECONNREFUSED' ? 0 : 5); }); \
        setTimeout(() => process.exit(3), 5000);";

    let allow_output = Command::new(&cli)
        .arg(&node)
        .arg("-e")
        .arg(loopback_script)
        .env_clear()
        .env("HOME", harness.home.path())
        .env("PATH", std::env::var_os("PATH").unwrap_or_default())
        .env("SENTINEL_HOOK_DYLIB", &dylib)
        .env("SENTINEL_STATE_DIR", &harness.state_dir)
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
        "allow leg: Sentinel denied loopback! D-18 allowlists 127.0.0.1. \
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
            "SKIP: {DENY_HOST}:{DENY_PORT} does not resolve outside Sentinel \
             (ISS-03 sanity gate)"
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
        .arg(&node)
        .arg(&script)
        .env_clear()
        .env("HOME", harness.home.path())
        .env("PATH", std::env::var_os("PATH").unwrap_or_default())
        .env("SENTINEL_HOOK_DYLIB", &dylib)
        .env("SENTINEL_STATE_DIR", &harness.state_dir)
        .env("PROBE_HOST", DENY_HOST)
        .env("PROBE_PORT", DENY_PORT)
        .env("PROBE_MODE", "resolve_connect")
        .stdin(std::process::Stdio::null()) // Non-TTY: is_tty=false
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .output()
        .expect("run sentinel");

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
    let sentinel_deny = stdout.contains("EHOSTUNREACH") || stdout.contains("ENOTFOUND");
    assert!(
        sentinel_deny,
        "non-TTY: expected EHOSTUNREACH (connect deny) or ENOTFOUND (DNS deny); \
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
            "SKIP: {DENY_HOST}:{DENY_PORT} does not resolve outside Sentinel \
             (ISS-03 sanity gate)"
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

    // This inline script exercises the EXACT flow that M005 enables:
    // 1. dns.lookup() calls getaddrinfo → hook proxies to daemon → gets IP
    // 2. hook caches IP→hostname mapping
    // 3. net.connect() to the resolved IP → hook looks up hostname from cache
    // 4. Policy evaluation on the hostname → DENY → EHOSTUNREACH
    //
    // Without M005's DNS cache, step 3 would see an unknown IP (cache miss)
    // and would either allow (wrong) or deny based on raw IP tier evaluation.
    // With M005, the hostname is recovered from cache and evaluated correctly.
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
        .arg(&node)
        .arg("-e")
        .arg(&inline)
        .env_clear()
        .env("HOME", harness.home.path())
        .env("PATH", std::env::var_os("PATH").unwrap_or_default())
        .env("SENTINEL_HOOK_DYLIB", &dylib)
        .env("SENTINEL_STATE_DIR", &harness.state_dir)
        .output()
        .expect("run sentinel");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    // The resolve should succeed (daemon proxies DNS).
    assert!(
        stdout.contains("RESOLVED"),
        "expected RESOLVED marker (daemon-proxied DNS); got:\n\
         stdout: {stdout}\nstderr: {stderr}"
    );

    // The connect to the resolved IP must be denied — the hook recovered
    // the hostname from the DNS cache and evaluated the policy.
    assert_eq!(
        output.status.code(),
        Some(42),
        "expected exit 42 (connect EHOSTUNREACH via cached hostname); got {:?}\n\
         stdout: {stdout}\nstderr: {stderr}",
        output.status.code()
    );

    assert!(
        stdout.contains("CONNECT-ERR") && stdout.contains("EHOSTUNREACH"),
        "expected CONNECT-ERR EHOSTUNREACH; got: {stdout}"
    );

    // UNEXPECTED-CONNECT-OK must NOT appear.
    assert!(
        !stdout.contains("UNEXPECTED-CONNECT-OK"),
        "connection to denied host succeeded — DNS cache did not populate \
         correctly or connect() did not check cached hostname. stdout: {stdout}"
    );
}

// ============================================================================
// Test 7: connect_evil.js now gets EHOSTUNREACH from the connect layer
//         (proves the getaddrinfo→cache→connect pipeline is working)
// ============================================================================

#[cfg_attr(not(target_os = "macos"), ignore)]
#[test]
fn connect_evil_denied_via_cached_hostname() {
    if !deny_target_resolves() {
        eprintln!(
            "SKIP: {DENY_HOST}:{DENY_PORT} does not resolve outside Sentinel"
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

    let output = Command::new(&cli)
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

    assert_eq!(
        output.status.code(),
        Some(2),
        "expected exit 2 (connect_evil deny); got {:?}\n\
         stdout: {stdout}\nstderr: {stderr}",
        output.status.code()
    );

    assert!(
        stdout.contains("CONNECT-FAILED"),
        "expected CONNECT-FAILED marker; got: {stdout}"
    );

    // With M005, Node calls getaddrinfo (proxied to daemon), gets IPs,
    // then connect() is denied via cached hostname → EHOSTUNREACH.
    // OR getaddrinfo itself denied (if policy gate fires) → ENOTFOUND.
    // Both are valid Sentinel-deny errnos.
    let sentinel_deny = stdout.contains("EHOSTUNREACH") || stdout.contains("ENOTFOUND");
    assert!(
        sentinel_deny,
        "expected EHOSTUNREACH (connect deny) or ENOTFOUND (getaddrinfo deny); \
         got: {stdout}"
    );

    // ECONNREFUSED = Sentinel let the connect through. Bug.
    assert!(
        !stdout.contains("ECONNREFUSED"),
        "ECONNREFUSED means Sentinel did not enforce. stdout: {stdout}"
    );
}
