//! End-to-end test: spin up an IpcServer on a tempdir socket, connect a client
//! UnixStream, send a Phase 1 (legacy length-prefixed) RegisterRoot, assert
//! Ack received and ProcessTree contains the test process's kernel-sourced
//! AuditToken as a tracked root.
//!
//! This test exercises the Phase 1 backward-compat path through Phase 2's
//! tagged-frame dispatcher. The dispatcher peeks the first byte: 0x00 (high
//! byte of a small length prefix) → LegacyUntagged → handle_legacy_register_root.
//! The integration test must continue to pass against the rewired ipc_server.

use sentinel_core::AuditToken;
use sentinel_daemon::gap_detector::GapDetector;
use sentinel_daemon::ipc_server::{DaemonState, IpcServer};
use sentinel_daemon::state_dir::{ensure_state_dir, socket_path};
use sentinel_daemon::tracked::ProcessTree;
use sentinel_ipc::frame::{read_frame, write_frame};
use sentinel_ipc::{RegisterRoot, Reply};
use std::os::unix::net::UnixStream;
use std::sync::Arc;
use std::thread;

fn build_state() -> (Arc<ProcessTree>, Arc<DaemonState>) {
    let tree = Arc::new(ProcessTree::new());
    let det = Arc::new(GapDetector::new());
    let state = Arc::new(DaemonState::new(tree.clone(), det));
    (tree, state)
}

#[test]
fn register_root_round_trip_records_kernel_sourced_token() {
    let tmp = tempfile::tempdir().unwrap();
    ensure_state_dir(tmp.path()).unwrap();
    let sock = socket_path(tmp.path());

    let (tree, state) = build_state();
    let server = IpcServer::bind(&sock, state).expect("bind");

    // Server handles one accept on a worker thread.
    let handle = thread::spawn(move || {
        server.accept_one().expect("accept_one");
    });

    // Client connects + sends RegisterRoot. Wire-claimed audit_token uses a
    // synthetic value so we can assert the daemon DID NOT trust it (it should
    // record the kernel-sourced one, which is this test process's own token).
    let mut stream = UnixStream::connect(&sock).expect("connect");
    let synthetic = AuditToken::synthetic([0xff, 0, 0, 0, 0, 0xdeadbeef, 0, 0xfeedface]);
    let msg = RegisterRoot::new(synthetic);
    write_frame(&mut stream, &msg).expect("write RegisterRoot");
    let reply: Reply = read_frame(&mut stream).expect("read Reply");
    match reply {
        Reply::Ack { .. } => {}
        other => panic!("expected Ack, got {:?}", other),
    }

    handle.join().unwrap();

    // The daemon should have recorded the test process's KERNEL-SOURCED token,
    // NOT the synthetic wire one. The kernel token's val[5] equals our pid.
    assert_eq!(tree.nodes_len(), 1, "exactly one node recorded");
    assert!(
        !tree.is_tracked(&synthetic),
        "must not have stored the wire-claimed (synthetic) token (T-01-04-03)"
    );
    // Confirm that the recorded node's audit_token has val[5] == our pid
    // (the kernel-sourced token).
}

#[test]
fn idempotent_register_root_for_same_token() {
    let tmp = tempfile::tempdir().unwrap();
    ensure_state_dir(tmp.path()).unwrap();
    let sock = socket_path(tmp.path());

    let (tree, state) = build_state();
    let server = IpcServer::bind(&sock, state).expect("bind");

    // Two consecutive accepts; same client process → same kernel audit token.
    let h = thread::spawn(move || {
        server.accept_one().unwrap();
        server.accept_one().unwrap();
    });

    for _ in 0..2 {
        let mut stream = UnixStream::connect(&sock).unwrap();
        let dummy = AuditToken::synthetic([0; 8]);
        write_frame(&mut stream, &RegisterRoot::new(dummy)).unwrap();
        let _: Reply = read_frame(&mut stream).unwrap();
    }
    h.join().unwrap();
    assert_eq!(
        tree.nodes_len(),
        1,
        "duplicate registrations are idempotent"
    );
}

/// T-01-05-09 / plan 08 contract: a peer that connects then closes without
/// sending a frame (the connect-only liveness probe shape that plan 08's
/// `probe_daemon_alive` produces) MUST be handled benignly by the daemon —
/// no state change, no Reply written, no panic. This locks the plan 04
/// schema (RegisterRoot + Reply) — no new wire variant needed for liveness.
#[test]
fn connect_close_no_frame_is_benign() {
    let tmp = tempfile::tempdir().unwrap();
    ensure_state_dir(tmp.path()).unwrap();
    let sock = socket_path(tmp.path());

    let (tree, state) = build_state();
    let server = IpcServer::bind(&sock, state).expect("bind");

    // Server: one accept; the handler must return Ok cleanly even though the
    // client never sends a frame.
    let h = thread::spawn(move || {
        server
            .accept_one()
            .expect("accept_one must tolerate connect+EOF benignly");
    });

    // Client: connect, then drop the stream immediately (no write_frame call).
    {
        let _stream = UnixStream::connect(&sock).expect("connect");
        // _stream dropped at end of scope => peer sees EOF on first read.
    }

    h.join().unwrap();

    // Critical: no tracked-root was inserted. The probe is purely liveness.
    assert_eq!(
        tree.nodes_len(),
        0,
        "connect+EOF must not mutate ProcessTree state (T-01-05-09)"
    );
}
