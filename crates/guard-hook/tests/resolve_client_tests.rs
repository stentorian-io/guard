#![cfg(target_os = "macos")]

//! `send_resolve_sync` round-trip tests (gap-closure 02-08).
//!
//! Stub daemon: spawn a thread that accepts on a tempdir Unix socket,
//! reads the tag byte (must be 0x06), reads the length-prefixed CBOR
//! Resolve body, and writes a length-prefixed CBOR `ResolveReply` tagged
//! with 0x06.
//!
//! Test 3: `NotConfigured` when `STT_GUARD_DAEMON_SOCKET` is unset.
//! Test 4: Addresses-OK — stub returns `ResolveReply::Addresses` with one v4 sockaddr.
//! Test 5: Deny — stub returns `ResolveReply::Deny` → `DaemonRejected` error.
//! Test 6: Timeout — stub accepts connection but never replies.
//!
//! NOTE: These tests share a global daemon socket override (`TEST_SOCKET_OVERRIDE`).
//! They MUST be serialized to avoid races. Each test acquires `SOCKET_TEST_LOCK`
//! before mutating the override.

/// Serialization lock for tests that mutate the daemon socket override.
/// Tests in this binary run in parallel by default; this lock ensures
/// only one test at a time holds the socket override.
static SOCKET_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

use guard_core::allowlist::{AllowlistEntry, MatchType, RuleKind, RuleTier};
use guard_hook::ipc_client::{
    _clear_daemon_socket_for_test, _set_daemon_socket_for_test, IpcClientError, send_resolve_sync,
};
use guard_hook::test_decide_for_sockaddr;
use guard_ipc::frame::{read_frame, write_frame};
use guard_ipc::{ResolveReply, SOCKADDR_WIRE_LEN};
use std::io::{Read, Write};
use std::os::unix::net::UnixListener;
use std::path::PathBuf;
use std::thread;
use std::time::Duration;
use tempfile::TempDir;

/// Build a canonical `AF_INET` sockaddr wire buffer for IP 1.2.3.4 port 443.
/// Layout matches daemon's `sockaddr_to_wire` from handlers/resolve.rs:
///   [0]=`sa_len(16)`, [1]=`AF_INET(2)`, [2..4]=443 BE, [4..8]=1.2.3.4, [8..28]=zeroes.
fn v4_sockaddr_1_2_3_4_443() -> [u8; SOCKADDR_WIRE_LEN] {
    let mut buf = [0u8; SOCKADDR_WIRE_LEN];
    buf[0] = 16; // sin_len
    buf[1] = 2; // AF_INET
    buf[2] = 0x01;
    buf[3] = 0xBB; // port 443 BE
    buf[4] = 1;
    buf[5] = 2;
    buf[6] = 3;
    buf[7] = 4; // 1.2.3.4
    buf
}

/// Spin up a stub Unix listener that accepts one connection, reads the tagged
/// frame, and replies with the given `ResolveReply`.
/// Returns (`TempDir` keeping the socket alive, socket path).
fn spawn_stub_resolver(reply: ResolveReply) -> (TempDir, PathBuf) {
    let dir = tempfile::tempdir().expect("tempdir for stub resolver");
    let sock_path = dir.path().join("stub_resolve.sock");
    let listener = UnixListener::bind(&sock_path).expect("bind stub socket");
    let reply_clone = reply;
    thread::spawn(move || {
        if let Ok((mut stream, _)) = listener.accept() {
            // Read the tag byte — must be TAG_RESOLVE = 0x06.
            let mut tag = [0u8; 1];
            if stream.read_exact(&mut tag).is_err() {
                return;
            }
            assert_eq!(tag[0], 0x06, "stub: expected TAG_RESOLVE = 0x06");
            // Read the length-prefixed CBOR Resolve body (discard — we don't need to parse it here).
            let _req: guard_ipc::Resolve =
                read_frame(&mut stream).expect("stub: read Resolve body");
            // Write the reply: tag 0x06 + length-prefixed CBOR ResolveReply.
            stream.write_all(&[0x06]).expect("stub: write reply tag");
            write_frame(&mut stream, &reply_clone).expect("stub: write ResolveReply");
        }
    });
    // Brief yield to let the listener thread start.
    thread::sleep(Duration::from_millis(10));
    (dir, sock_path)
}

/// Stub that accepts the connection but never replies (for timeout test).
fn spawn_stub_no_reply() -> (TempDir, PathBuf) {
    let dir = tempfile::tempdir().expect("tempdir for no-reply stub");
    let sock_path = dir.path().join("stub_no_reply.sock");
    let listener = UnixListener::bind(&sock_path).expect("bind no-reply stub");
    thread::spawn(move || {
        if let Ok((_stream, _)) = listener.accept() {
            // Accept but never write — connection hangs.
            thread::sleep(Duration::from_secs(30));
        }
    });
    thread::sleep(Duration::from_millis(10));
    (dir, sock_path)
}

// ---- Test 3: NotConfigured when no daemon socket configured ----

#[cfg_attr(not(target_os = "macos"), ignore = "macOS-only test")]
#[test]
fn send_resolve_sync_not_configured_when_socket_unset() {
    let _lock = SOCKET_TEST_LOCK.lock().unwrap();
    // Ensure no test override is set.
    _clear_daemon_socket_for_test();
    let result = send_resolve_sync("registry.npmjs.org", 443, 100);
    assert!(
        matches!(result, Err(IpcClientError::NotConfigured)),
        "expected NotConfigured when STT_GUARD_DAEMON_SOCKET is unset; got: {result:?}"
    );
}

// ---- Test 4: Addresses-OK ----

#[cfg_attr(not(target_os = "macos"), ignore = "macOS-only test")]
#[test]
fn send_resolve_sync_returns_addresses_on_ok_reply() {
    let _lock = SOCKET_TEST_LOCK.lock().unwrap();
    let expected_addr = v4_sockaddr_1_2_3_4_443();
    let reply = ResolveReply::addresses(vec![expected_addr]);
    let (_dir, sock_path) = spawn_stub_resolver(reply);
    _set_daemon_socket_for_test(sock_path);

    let result = send_resolve_sync("example.com", 443, 250);
    _clear_daemon_socket_for_test();

    let addrs = result.expect("expected Ok(addrs) from stub returning Addresses");
    assert_eq!(addrs.len(), 1, "stub returned 1 address");
    assert_eq!(
        addrs[0], expected_addr,
        "returned sockaddr must match stub's v4 layout"
    );
    // Verify the 28-byte layout: sa_len=16, AF_INET=2, port 443 BE, IP 1.2.3.4
    assert_eq!(addrs[0][0], 16, "byte[0] = sa_len = 16");
    assert_eq!(addrs[0][1], 2, "byte[1] = AF_INET = 2");
    assert_eq!(addrs[0][2], 0x01, "byte[2] = port high = 0x01");
    assert_eq!(addrs[0][3], 0xBB, "byte[3] = port low = 0xBB (443)");
    assert_eq!(&addrs[0][4..8], &[1, 2, 3, 4], "bytes[4..8] = IP 1.2.3.4");
}

// ---- Test 5: Deny → DaemonRejected ----

#[cfg_attr(not(target_os = "macos"), ignore = "macOS-only test")]
#[test]
fn send_resolve_sync_returns_daemon_rejected_on_deny_reply() {
    let _lock = SOCKET_TEST_LOCK.lock().unwrap();
    let reply = ResolveReply::deny("blocked");
    let (_dir, sock_path) = spawn_stub_resolver(reply);
    _set_daemon_socket_for_test(sock_path);

    let result = send_resolve_sync("evil.example.com", 443, 250);
    _clear_daemon_socket_for_test();

    assert!(
        matches!(result, Err(IpcClientError::DaemonRejected(ref m)) if m == "blocked"),
        "expected DaemonRejected(\"blocked\"); got: {result:?}"
    );
}

// ---- Test 6: Timeout — stub never replies ----

#[cfg_attr(not(target_os = "macos"), ignore = "macOS-only test")]
#[test]
fn send_resolve_sync_returns_timeout_when_stub_hangs() {
    let _lock = SOCKET_TEST_LOCK.lock().unwrap();
    let (_dir, sock_path) = spawn_stub_no_reply();
    _set_daemon_socket_for_test(sock_path);

    let result = send_resolve_sync("timeout.example.com", 443, 100);
    _clear_daemon_socket_for_test();

    assert!(
        matches!(result, Err(IpcClientError::Timeout)),
        "expected Timeout when stub never replies; got: {result:?}"
    );
}

// ---- Test 7: Wired end-to-end — decide_for_sockaddr uses Resolve-IPC on cache miss ----
//
// This test verifies the full chain:
//   decide_for_sockaddr(1.2.3.4:443) [cache miss]
//     → send_resolve_sync("example.com", 443, ...) via stub
//     → stub replies Addresses([1.2.3.4:443])
//     → cache populated with (sockaddr, "example.com")
//     → evaluate_policy(host="example.com", ..., resolved_via_getaddrinfo=true)
//     → Tier 1 CuratedAllow fires → Verdict::Allow
//
// Note: ALLOWLIST is a OnceLock set at most once per process. In a test binary,
// the first test that calls test_decide_for_sockaddr will set it. Subsequent
// tests in the same process see the same ALLOWLIST. Run this test in isolation
// or ensure all tests use compatible entries. Since this is the only test that
// calls test_decide_for_sockaddr, it has exclusive control over the OnceLock.

#[cfg_attr(not(target_os = "macos"), ignore = "macOS-only test")]
#[test]
fn decide_for_sockaddr_allows_curated_host_via_resolve_ipc() {
    let _lock = SOCKET_TEST_LOCK.lock().unwrap();
    let expected_addr = v4_sockaddr_1_2_3_4_443();
    let reply = ResolveReply::addresses(vec![expected_addr]);
    let (_dir, sock_path) = spawn_stub_resolver(reply);
    _set_daemon_socket_for_test(sock_path);

    // AllowlistEntry for example.com at CuratedAllow tier, Exact match.
    let entries = vec![AllowlistEntry {
        kind: RuleKind::Allow,
        tier: RuleTier::CuratedAllow,
        match_type: MatchType::Exact,
        pattern: "example.com".to_string(),
        reason: "test entry for resolve-ipc gap-closure".to_string(),
    }];

    // Build a raw AF_INET sockaddr_in for 1.2.3.4:443. This test only runs on
    // macOS, but the ignored Linux target still has to type-check this body.
    let mut sa: libc::sockaddr_in = unsafe { std::mem::zeroed() };
    #[cfg(target_os = "macos")]
    {
        sa.sin_len = 16;
    }
    sa.sin_family = libc::sa_family_t::try_from(libc::AF_INET).unwrap_or(0);
    sa.sin_port = 443u16.to_be();
    sa.sin_addr = libc::in_addr {
        s_addr: u32::from_be_bytes([1, 2, 3, 4]).to_be(),
    };
    let addrlen = libc::socklen_t::try_from(std::mem::size_of::<libc::sockaddr_in>()).unwrap_or(0);

    let verdict =
        unsafe { test_decide_for_sockaddr(entries, &raw mut sa as *const libc::sockaddr, addrlen) };
    _clear_daemon_socket_for_test();

    assert_eq!(
        verdict,
        guard_core::Verdict::Allow,
        "decide_for_sockaddr must return Allow for a curated-allowlisted host \
         resolved via Resolve-IPC cache-miss path"
    );
}
