//! send_resolve_sync round-trip tests (gap-closure 02-08).
//!
//! Stub daemon: spawn a thread that accepts on a tempdir Unix socket,
//! reads the tag byte (must be 0x06), reads the length-prefixed CBOR
//! Resolve body, and writes a length-prefixed CBOR ResolveReply tagged
//! with 0x06.
//!
//! Test 3: NotConfigured when SENTINEL_DAEMON_SOCKET is unset.
//! Test 4: Addresses-OK — stub returns ResolveReply::Addresses with one v4 sockaddr.
//! Test 5: Deny — stub returns ResolveReply::Deny → DaemonRejected error.
//! Test 6: Timeout — stub accepts connection but never replies.

use sentinel_hook::ipc_client::{_clear_daemon_socket_for_test, _set_daemon_socket_for_test, send_resolve_sync, IpcClientError};
use sentinel_ipc::frame::{read_frame, write_frame};
use sentinel_ipc::{ResolveReply, SOCKADDR_WIRE_LEN};
use std::io::{Read, Write};
use std::os::unix::net::UnixListener;
use std::path::PathBuf;
use std::thread;
use std::time::Duration;
use tempfile::TempDir;

/// Build a canonical AF_INET sockaddr wire buffer for IP 1.2.3.4 port 443.
/// Layout matches daemon's sockaddr_to_wire from handlers/resolve.rs:
///   [0]=sa_len(16), [1]=AF_INET(2), [2..4]=443 BE, [4..8]=1.2.3.4, [8..28]=zeroes.
fn v4_sockaddr_1_2_3_4_443() -> [u8; SOCKADDR_WIRE_LEN] {
    let mut buf = [0u8; SOCKADDR_WIRE_LEN];
    buf[0] = 16; // sin_len
    buf[1] = 2;  // AF_INET
    buf[2] = 0x01;
    buf[3] = 0xBB; // port 443 BE
    buf[4] = 1;
    buf[5] = 2;
    buf[6] = 3;
    buf[7] = 4; // 1.2.3.4
    buf
}

/// Spin up a stub Unix listener that accepts one connection, reads the tagged
/// frame, and replies with the given ResolveReply.
/// Returns (TempDir keeping the socket alive, socket path).
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
            let _req: sentinel_ipc::Resolve = read_frame(&mut stream).expect("stub: read Resolve body");
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

#[cfg_attr(not(target_os = "macos"), ignore)]
#[test]
fn send_resolve_sync_not_configured_when_socket_unset() {
    // Ensure no test override is set.
    _clear_daemon_socket_for_test();
    let result = send_resolve_sync("registry.npmjs.org", 443, 100);
    assert!(
        matches!(result, Err(IpcClientError::NotConfigured)),
        "expected NotConfigured when SENTINEL_DAEMON_SOCKET is unset; got: {:?}",
        result
    );
}

// ---- Test 4: Addresses-OK ----

#[cfg_attr(not(target_os = "macos"), ignore)]
#[test]
fn send_resolve_sync_returns_addresses_on_ok_reply() {
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

#[cfg_attr(not(target_os = "macos"), ignore)]
#[test]
fn send_resolve_sync_returns_daemon_rejected_on_deny_reply() {
    let reply = ResolveReply::deny("blocked");
    let (_dir, sock_path) = spawn_stub_resolver(reply);
    _set_daemon_socket_for_test(sock_path);

    let result = send_resolve_sync("evil.example.com", 443, 250);
    _clear_daemon_socket_for_test();

    assert!(
        matches!(result, Err(IpcClientError::DaemonRejected(ref m)) if m == "blocked"),
        "expected DaemonRejected(\"blocked\"); got: {:?}",
        result
    );
}

// ---- Test 6: Timeout — stub never replies ----

#[cfg_attr(not(target_os = "macos"), ignore)]
#[test]
fn send_resolve_sync_returns_timeout_when_stub_hangs() {
    let (_dir, sock_path) = spawn_stub_no_reply();
    _set_daemon_socket_for_test(sock_path);

    let result = send_resolve_sync("timeout.example.com", 443, 100);
    _clear_daemon_socket_for_test();

    assert!(
        matches!(result, Err(IpcClientError::Timeout)),
        "expected Timeout when stub never replies; got: {:?}",
        result
    );
}
