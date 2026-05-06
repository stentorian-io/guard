//! TREE-06 gap-closure 02-09 — EnvNotPropagatedGap round-trip tests.
//!
//! Tests the daemon-side handler for tag 0x08 (EnvNotPropagatedGap IPC).
//!
//! Design note on peer-auth and gap recording (REGISTER-01 + peer_token design):
//!   The daemon's is_tracked check uses the KERNEL-sourced peer token
//!   (from LOCAL_PEERTOKEN). The ProcessTree is keyed by AuditToken.
//!
//!   For a test to pass the is_tracked gate, the test process's kernel token
//!   must be in the tree. We register it via RegisterRoot with wire_pid =
//!   getpid() (self-registration path), which causes the daemon to call
//!   insert_root(kernel_peer_token, ...).
//!
//!   After the REGISTER-01 + peer_token design change, the gap is recorded
//!   on the PEER's node (peer_token = the process that calls posix_spawn).
//!   The wire's parent_audit_token is advisory only.
//!
//!   To locate the gap in the tree after the test, we use `tree.nodes_len()`
//!   and `tree.get_node_by_pid` (via a scan helper) — the kernel peer token
//!   has val[5] == getpid(), so we can find it by pid.
//!
//! Test 1: round-trip — daemon records gap on the peer's own tree node.
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
///
/// REGISTER-01 self-registration path: wire_pid == kernel_pid.
/// When wire_pid == kernel_pid, the daemon registers the kernel-sourced peer
/// token (the test process's own full 8-field token).
fn register_self_as_tracked(sock: &std::path::Path) {
    let self_pid = unsafe { libc::getpid() } as u32;
    let self_token = AuditToken { val: [0, 0, 0, 0, 0, self_pid, 0, 0] };
    let msg = RegisterRoot::new(self_token);
    let mut stream = UnixStream::connect(sock).expect("connect RegisterRoot");
    write_frame(&mut stream, &msg).expect("write RegisterRoot");
    let _: Reply = read_frame(&mut stream).expect("read Reply");
}

/// Find the CoverageGap on any node whose audit_token.val[5] matches `pid`.
/// Uses ProcessTree::find_node_by_pid which scans all nodes by pid field.
fn find_gap_by_pid(tree: &ProcessTree, pid: u32) -> Option<CoverageGap> {
    tree.find_node_by_pid(pid).and_then(|n| n.coverage_gap)
}

// ---- Test 1: round-trip records CoverageGap::EnvNotPropagated on the peer's node ----

#[test]
fn env_not_propagated_gap_round_trip_records_gap_on_parent() {
    let tmp = tempfile::tempdir().unwrap();
    ensure_state_dir(tmp.path()).unwrap();
    let sock = socket_path(tmp.path());

    let (tree, state) = build_state(tmp.path());

    let server = IpcServer::bind(&sock, state.clone()).expect("bind");
    // Accept two connections: RegisterRoot then EnvNotPropagatedGap.
    let h = thread::spawn(move || {
        server.accept_one().expect("accept RegisterRoot");
        server.accept_one().expect("accept gap");
    });

    // Register self so kernel peer token is in the tree (satisfies is_tracked check).
    register_self_as_tracked(&sock);

    // Send the gap. The parent_audit_token is advisory; the daemon records
    // the gap on peer_token (the connecting process's kernel token).
    let self_pid = unsafe { libc::getpid() } as u32;
    let advisory_parent = AuditTokenWire {
        val: [0, 0, 0, 0, 0, self_pid, 0, 0],
    };
    let gap = EnvNotPropagatedGap::new(advisory_parent, b"/usr/bin/child".to_vec(), 123456789);
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

    // (b) The ProcessTree must have recorded the gap on the peer's node.
    //     The peer's kernel token has val[5] == self_pid. We scan to find it.
    let gap_found = find_gap_by_pid(&tree, self_pid);
    match gap_found {
        Some(CoverageGap::EnvNotPropagated {
            ref binary_path,
            detected_at_ms,
        }) => {
            assert_eq!(binary_path, "/usr/bin/child", "binary_path must match");
            assert_eq!(detected_at_ms, 123456789, "detected_at_ms must match");
        }
        other => panic!(
            "expected CoverageGap::EnvNotPropagated on peer node, got: {:?}",
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

    // Server accepts 3 connections: RegisterRoot + 2 gaps.
    let server = IpcServer::bind(&sock, state.clone()).expect("bind");
    let h = thread::spawn(move || {
        server.accept_one().expect("accept RegisterRoot");
        server.accept_one().expect("accept gap 1");
        server.accept_one().expect("accept gap 2");
    });

    register_self_as_tracked(&sock);

    let self_pid = unsafe { libc::getpid() } as u32;
    let advisory_parent = AuditTokenWire {
        val: [0, 0, 0, 0, 0, self_pid, 0, 0],
    };

    // First gap.
    {
        let gap1 = EnvNotPropagatedGap::new(advisory_parent, b"/first/child".to_vec(), 1000);
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
        let gap2 = EnvNotPropagatedGap::new(advisory_parent, b"/second/child".to_vec(), 2000);
        let mut stream = UnixStream::connect(&sock).expect("connect gap2");
        let ack = send_env_gap_and_recv_ack(&mut stream, &gap2);
        assert!(
            matches!(ack, EnvNotPropagatedGapAck::Ok { .. }),
            "second gap ack must be Ok; got: {:?}",
            ack
        );
    }

    h.join().unwrap();

    // The peer's node must have the SECOND gap (overwrite / last-writer-wins).
    let gap_found = find_gap_by_pid(&tree, self_pid);
    match gap_found {
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
