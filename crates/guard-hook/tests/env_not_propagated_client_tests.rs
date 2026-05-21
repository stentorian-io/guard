//! send_env_not_propagated_gap_sync round-trip tests (TREE-06 gap-closure 02-09).
//!
//! Stub daemon: spawn a thread that accepts on a tempdir Unix socket,
//! reads tag 0x08, reads the length-prefixed CBOR EnvNotPropagatedGap body,
//! and writes an EnvNotPropagatedGapAck reply.
//!
//! Test 1: stub returns Ack::Ok → Ok(()).
//! Test 2: stub returns Ack::Err → Err(IpcClientError::DaemonRejected(message)).
//! Test 3: stub never replies → Err(IpcClientError::Timeout).
//!
//! NOTE: These tests share the global TEST_SOCKET_OVERRIDE. They MUST be
//! serialized to avoid races. Each test acquires SOCKET_TEST_LOCK first.

static SOCKET_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

use guard_hook::ipc_client::{
    _clear_daemon_socket_for_test, _set_daemon_socket_for_test, IpcClientError,
    send_env_not_propagated_gap_sync,
};
use guard_ipc::frame::{read_frame, write_frame};
use guard_ipc::{AuditTokenWire, EnvNotPropagatedGap, EnvNotPropagatedGapAck};
use std::io::{Read, Write};
use std::os::unix::net::UnixListener;
use std::path::PathBuf;
use std::thread;
use std::time::Duration;
use tempfile::TempDir;

/// Spawn a stub Unix socket that accepts one connection, reads the 0x08 tag + CBOR body,
/// and replies with the given EnvNotPropagatedGapAck.
fn spawn_stub_env_gap_daemon(reply: EnvNotPropagatedGapAck) -> (TempDir, PathBuf) {
    let dir = tempfile::tempdir().expect("tempdir");
    let sock_path = dir.path().join("stub_env_gap.sock");
    let listener = UnixListener::bind(&sock_path).expect("bind stub socket");
    thread::spawn(move || {
        if let Ok((mut stream, _)) = listener.accept() {
            let mut tag = [0u8; 1];
            if stream.read_exact(&mut tag).is_err() {
                return;
            }
            assert_eq!(tag[0], 0x08, "stub: expected tag 0x08");
            // Read body (discard).
            let _req: EnvNotPropagatedGap = match read_frame(&mut stream) {
                Ok(r) => r,
                Err(_) => return,
            };
            // Write reply: echo tag 0x08 + CBOR ack.
            stream.write_all(&[0x08]).expect("stub: write reply tag");
            write_frame(&mut stream, &reply).expect("stub: write ack");
        }
    });
    thread::sleep(Duration::from_millis(10));
    (dir, sock_path)
}

/// Stub that accepts but never replies (for timeout test).
fn spawn_stub_no_reply_env_gap() -> (TempDir, PathBuf) {
    let dir = tempfile::tempdir().expect("tempdir");
    let sock_path = dir.path().join("stub_no_reply_env_gap.sock");
    let listener = UnixListener::bind(&sock_path).expect("bind stub socket");
    thread::spawn(move || {
        if let Ok((_stream, _)) = listener.accept() {
            thread::sleep(Duration::from_secs(30));
        }
    });
    thread::sleep(Duration::from_millis(10));
    (dir, sock_path)
}

fn dummy_parent() -> AuditTokenWire {
    AuditTokenWire {
        val: [0, 0, 0, 0, 0, 12345, 0, 1],
    }
}

// ---- Test 1: stub returns Ack::Ok ----

#[cfg_attr(not(target_os = "macos"), ignore)]
#[test]
fn send_env_not_propagated_gap_sync_ok_reply() {
    let _lock = SOCKET_TEST_LOCK.lock().unwrap();
    let (_dir, sock_path) = spawn_stub_env_gap_daemon(EnvNotPropagatedGapAck::ok());
    _set_daemon_socket_for_test(sock_path);

    let result =
        send_env_not_propagated_gap_sync(dummy_parent(), b"/usr/bin/example", 123456789, 250);
    _clear_daemon_socket_for_test();

    assert!(
        result.is_ok(),
        "expected Ok(()) on Ack::Ok; got: {:?}",
        result
    );
}

// ---- Test 2: stub returns Ack::Err → DaemonRejected ----

#[cfg_attr(not(target_os = "macos"), ignore)]
#[test]
fn send_env_not_propagated_gap_sync_err_reply_returns_daemon_rejected() {
    let _lock = SOCKET_TEST_LOCK.lock().unwrap();
    let (_dir, sock_path) = spawn_stub_env_gap_daemon(EnvNotPropagatedGapAck::err(
        "untracked peer; ignoring env-not-propagated gap",
    ));
    _set_daemon_socket_for_test(sock_path);

    let result = send_env_not_propagated_gap_sync(dummy_parent(), b"/usr/bin/example", 999, 250);
    _clear_daemon_socket_for_test();

    assert!(
        matches!(
            result,
            Err(IpcClientError::DaemonRejected(ref m)) if m.contains("untracked peer")
        ),
        "expected DaemonRejected; got: {:?}",
        result
    );
}

// ---- Test 3: stub never replies → Timeout ----

#[cfg_attr(not(target_os = "macos"), ignore)]
#[test]
fn send_env_not_propagated_gap_sync_timeout_when_stub_hangs() {
    let _lock = SOCKET_TEST_LOCK.lock().unwrap();
    let (_dir, sock_path) = spawn_stub_no_reply_env_gap();
    _set_daemon_socket_for_test(sock_path);

    let result = send_env_not_propagated_gap_sync(
        dummy_parent(),
        b"/usr/bin/example",
        0,
        100, // 100ms timeout → should timeout fast
    );
    _clear_daemon_socket_for_test();

    assert!(
        matches!(result, Err(IpcClientError::Timeout)),
        "expected Timeout when stub never replies; got: {:?}",
        result
    );
}
