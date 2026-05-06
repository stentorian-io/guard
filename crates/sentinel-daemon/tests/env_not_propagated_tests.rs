//! TREE-06 gap-closure 02-09 — EnvNotPropagatedGap round-trip tests.
//!
//! Tests the daemon-side handler for tag 0x08 (EnvNotPropagatedGap IPC).
//!
//! Design note on peer-auth in tests:
//!   The daemon's is_tracked check uses the KERNEL-sourced peer token
//!   (from LOCAL_PEERCRED / audit_token). The ProcessTree is keyed by
//!   AuditToken, so for a test to pass the is_tracked gate, the test
//!   process's kernel token must be in the tree.
//!
//!   We register the kernel token via RegisterRoot (Phase 1 wire) which
//!   causes the daemon to call insert_root(kernel_peer_token, ...).
//!   We separately pre-insert a distinct "parent" node so set_coverage_gap
//!   has something to update.
//!
//! Test 1: round-trip — daemon records gap on a pre-inserted parent node.
//! Test 2: untracked peer → daemon replies Err with "untracked peer" message.
//! Test 3: two consecutive gaps → second overwrites first (last-writer-wins).
//! Test 4: ipc_dispatch MessageTag::EnvNotPropagatedGap byte value = 0x08.

use sentinel_core::AuditToken;
use sentinel_daemon::gap_detector::GapDetector;
use sentinel_daemon::ipc_server::{DaemonState, IpcServer};
use sentinel_daemon::rule_store::RuleStore;
use sentinel_daemon::state_dir::{db_path, ensure_state_dir, socket_path};
use sentinel_daemon::tracked::{CoverageGap, ProcessTree};
use sentinel_ipc::frame::{read_frame, write_frame};
use sentinel_ipc::{
    AuditTokenWire, EnvNotPropagatedGap, EnvNotPropagatedGapAck, IPC_SCHEMA_V2, RegisterRoot, Reply,
};
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::sync::Arc;
use std::thread;

fn build_state(state_dir: &std::path::Path) -> (Arc<ProcessTree>, Arc<DaemonState>) {
    let tree = Arc::new(ProcessTree::new());
    let det = Arc::new(GapDetector::new());
    let rs = Arc::new(RuleStore::open(&db_path(state_dir)).expect("open rule store"));
    let curated = Arc::new(Vec::new());
    let state = Arc::new(DaemonState::new(
        tree.clone(),
        det,
        rs,
        curated,
        state_dir.to_path_buf(),
    ));
    (tree, state)
}

/// Send a tagged EnvNotPropagatedGap (tag 0x08) frame and read back the Ack.
fn send_env_gap_and_recv_ack(
    stream: &mut UnixStream,
    gap: &EnvNotPropagatedGap,
) -> EnvNotPropagatedGapAck {
    stream.write_all(&[0x08]).expect("write tag byte");
    write_frame(stream, gap).expect("write gap body");
    let mut tag_back = [0u8; 1];
    stream.read_exact(&mut tag_back).expect("read reply tag");
    assert_eq!(tag_back[0], 0x08, "reply tag must echo 0x08");
    read_frame(stream).expect("read EnvNotPropagatedGapAck")
}

/// Register this test process as a tracked root via RegisterRoot (uses real peer-auth).
/// The daemon's handler will record the kernel-sourced peer token into the tree.
fn register_self_as_tracked(sock: &std::path::Path) {
    let dummy = AuditToken { val: [0u32; 8] };
    let msg = RegisterRoot::new(dummy);
    let mut stream = UnixStream::connect(sock).expect("connect RegisterRoot");
    write_frame(&mut stream, &msg).expect("write RegisterRoot");
    let _: Reply = read_frame(&mut stream).expect("read Reply");
}

// ---- Test 1: round-trip records CoverageGap::EnvNotPropagated on parent ----

#[test]
fn env_not_propagated_gap_round_trip_records_gap_on_parent() {
    let tmp = tempfile::tempdir().unwrap();
    ensure_state_dir(tmp.path()).unwrap();
    let sock = socket_path(tmp.path());

    let (tree, state) = build_state(tmp.path());

    // Pre-insert a distinct "parent" node the gap will be recorded on.
    // We use our_pid+1 so the key is different from the kernel peer token.
    let our_pid = unsafe { libc::getpid() } as u32;
    let wire_parent = AuditTokenWire {
        val: [0, 0, 0, 0, 0, our_pid.wrapping_add(1), 0, 0],
    };
    let parent_key: AuditToken = wire_parent.into();
    tree.insert_root(
        parent_key,
        "run-test1".to_string(),
        "/usr/bin/example".to_string(),
    );

    let server = IpcServer::bind(&sock, state.clone()).expect("bind");
    // Accept two connections: RegisterRoot then EnvNotPropagatedGap.
    let h = thread::spawn(move || {
        server.accept_one().expect("accept RegisterRoot");
        server.accept_one().expect("accept gap");
    });

    // Register self so kernel peer token is in the tree (satisfies is_tracked check).
    register_self_as_tracked(&sock);

    // Send the gap pointing at the parent node.
    let gap = EnvNotPropagatedGap::new(wire_parent, b"/usr/bin/child".to_vec(), 123456789);
    let mut stream = UnixStream::connect(&sock).expect("connect gap");
    let ack = send_env_gap_and_recv_ack(&mut stream, &gap);
    drop(stream);
    h.join().unwrap();

    // (a) Ack must be Ok.
    assert!(
        matches!(ack, EnvNotPropagatedGapAck::Ok { schema_version } if schema_version == IPC_SCHEMA_V2),
        "expected Ok ack; got: {:?}",
        ack
    );

    // (b) The ProcessTree must have recorded the gap on parent_key.
    let node = tree.get_node(&parent_key).expect("parent node must exist");
    match node.coverage_gap {
        Some(CoverageGap::EnvNotPropagated {
            ref binary_path,
            detected_at_ms,
        }) => {
            assert_eq!(binary_path, "/usr/bin/child", "binary_path must match");
            assert_eq!(detected_at_ms, 123456789, "detected_at_ms must match");
        }
        other => panic!(
            "expected CoverageGap::EnvNotPropagated, got: {:?}",
            other
        ),
    }
}

// ---- Test 2: untracked peer → Err reply, no gap recorded ----

#[test]
fn env_not_propagated_gap_untracked_peer_returns_err() {
    let tmp = tempfile::tempdir().unwrap();
    ensure_state_dir(tmp.path()).unwrap();
    let sock = socket_path(tmp.path());

    let (tree, state) = build_state(tmp.path());
    // Do NOT insert any root — the connecting peer will be "untracked".

    let server = IpcServer::bind(&sock, state.clone()).expect("bind");
    let h = thread::spawn(move || {
        server.accept_one().expect("accept_one");
    });

    let mut stream = UnixStream::connect(&sock).expect("connect");
    let synthetic_parent = AuditTokenWire {
        val: [0, 0, 0, 0, 0, 0xdeadbeef, 0, 1],
    };
    let gap = EnvNotPropagatedGap::new(synthetic_parent, b"/usr/bin/evil".to_vec(), 999);
    let ack = send_env_gap_and_recv_ack(&mut stream, &gap);
    drop(stream);
    h.join().unwrap();

    // Ack must be Err with "untracked peer" substring.
    match ack {
        EnvNotPropagatedGapAck::Err {
            schema_version,
            ref message,
        } => {
            assert_eq!(schema_version, IPC_SCHEMA_V2);
            assert!(
                message.contains("untracked peer"),
                "error message must contain 'untracked peer'; got: {}",
                message
            );
        }
        other => panic!("expected Err ack; got: {:?}", other),
    }

    // ProcessTree must be empty (no gap recorded).
    assert_eq!(tree.nodes_len(), 0, "no node should have been inserted");
}

// ---- Test 3: two consecutive gaps → second overwrites first (last-writer-wins) ----

#[test]
fn env_not_propagated_gap_second_overwrites_first() {
    let tmp = tempfile::tempdir().unwrap();
    ensure_state_dir(tmp.path()).unwrap();
    let sock = socket_path(tmp.path());

    let (tree, state) = build_state(tmp.path());

    let our_pid = unsafe { libc::getpid() } as u32;
    let wire_parent = AuditTokenWire {
        val: [0, 0, 0, 0, 0, our_pid.wrapping_add(1000), 0, 0],
    };
    let parent_key: AuditToken = wire_parent.into();
    tree.insert_root(parent_key, "run-test3".to_string(), "/usr/bin/npm".to_string());

    // Server accepts 3 connections: RegisterRoot + 2 gaps.
    let server = IpcServer::bind(&sock, state.clone()).expect("bind");
    let h = thread::spawn(move || {
        server.accept_one().expect("accept RegisterRoot");
        server.accept_one().expect("accept gap 1");
        server.accept_one().expect("accept gap 2");
    });

    register_self_as_tracked(&sock);

    // First gap.
    {
        let gap1 = EnvNotPropagatedGap::new(wire_parent, b"/first/child".to_vec(), 1000);
        let mut stream = UnixStream::connect(&sock).expect("connect gap1");
        let ack = send_env_gap_and_recv_ack(&mut stream, &gap1);
        assert!(
            matches!(ack, EnvNotPropagatedGapAck::Ok { .. }),
            "first gap ack must be Ok; got: {:?}",
            ack
        );
    }

    // Second gap — different binary_path and timestamp.
    {
        let gap2 = EnvNotPropagatedGap::new(wire_parent, b"/second/child".to_vec(), 2000);
        let mut stream = UnixStream::connect(&sock).expect("connect gap2");
        let ack = send_env_gap_and_recv_ack(&mut stream, &gap2);
        assert!(
            matches!(ack, EnvNotPropagatedGapAck::Ok { .. }),
            "second gap ack must be Ok; got: {:?}",
            ack
        );
    }

    h.join().unwrap();

    // The node must have the SECOND gap (overwrite / last-writer-wins).
    let node = tree.get_node(&parent_key).expect("parent node");
    match node.coverage_gap {
        Some(CoverageGap::EnvNotPropagated {
            ref binary_path,
            detected_at_ms,
        }) => {
            assert_eq!(
                binary_path, "/second/child",
                "second gap must overwrite first"
            );
            assert_eq!(
                detected_at_ms, 2000,
                "detected_at_ms must be from second gap"
            );
        }
        other => panic!(
            "expected EnvNotPropagated from second gap, got: {:?}",
            other
        ),
    }
}

// ---- Test 4: ipc_dispatch MessageTag::EnvNotPropagatedGap byte value ----

#[test]
fn message_tag_env_not_propagated_gap_byte_value() {
    use sentinel_daemon::ipc_dispatch::MessageTag;
    assert_eq!(
        MessageTag::EnvNotPropagatedGap.as_byte(),
        0x08,
        "EnvNotPropagatedGap must be tag byte 0x08"
    );
    assert_eq!(
        MessageTag::from_byte(0x08),
        Some(MessageTag::EnvNotPropagatedGap),
        "from_byte(0x08) must return EnvNotPropagatedGap"
    );
}
