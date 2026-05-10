//! Integration test: DenyNotify round-trip (D-39).
//!
//! Sends a DenyNotify tagged frame (tag 0x12) to the daemon and verifies:
//!   1. DenyNotifyAck::Ok received
//!   2. JSONL log contains a "block" row with source_kind="hook_deny"
//!   3. LogWriter blocks_today counter incremented

use sentinel_core::AuditToken;
use sentinel_daemon::gap_detector::GapDetector;
use sentinel_daemon::ipc_server::{DaemonState, IpcServer};
use sentinel_daemon::log_writer::LogWriter;
use sentinel_daemon::rule_store::RuleStore;
use sentinel_daemon::state_dir::{db_path, ensure_state_dir, socket_path};
use sentinel_daemon::tracked::ProcessTree;
use sentinel_ipc::frame::{read_frame, write_frame};
use sentinel_ipc::{AuditTokenWire, DenyNotify, DenyNotifyAck, IPC_SCHEMA_V4, RegisterRoot, Reply};
use std::io::{Read, Write as _};
use std::os::unix::net::UnixStream;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::thread;

fn register_self_as_tracked(sock: &std::path::Path) {
    let self_pid = unsafe { libc::getpid() } as u32;
    let self_token = AuditToken {
        val: [0, 0, 0, 0, 0, self_pid, 0, 0],
    };
    let msg = RegisterRoot::new(self_token);
    let mut stream = UnixStream::connect(sock).expect("connect RegisterRoot");
    write_frame(&mut stream, &msg).expect("write RegisterRoot");
    let _: Reply = read_frame(&mut stream).expect("read Reply");
}

fn send_deny_notify_and_recv_ack(
    stream: &mut UnixStream,
    msg: &DenyNotify,
) -> DenyNotifyAck {
    stream.write_all(&[0x12]).expect("write tag byte");
    write_frame(stream, msg).expect("write DenyNotify body");
    let mut tag_back = [0u8; 1];
    stream.read_exact(&mut tag_back).expect("read reply tag");
    assert_eq!(tag_back[0], 0x12, "reply tag must echo 0x12");
    read_frame(stream).expect("read DenyNotifyAck")
}

#[test]
fn deny_notify_round_trip_logs_block_row() {
    let tmp = tempfile::tempdir().unwrap();
    ensure_state_dir(tmp.path()).unwrap();
    let sock = socket_path(tmp.path());
    let log_path = tmp.path().join("sentinel.log");

    let tree = Arc::new(ProcessTree::new());
    let det = Arc::new(GapDetector::new());
    let rs = Arc::new(RuleStore::open(&db_path(tmp.path())).expect("open rule store"));
    let curated = Arc::new(Vec::new());

    let mut state = DaemonState::new(
        tree.clone(),
        det,
        rs,
        curated,
        tmp.path().to_path_buf(),
    );
    let log_writer = LogWriter::spawn(log_path.clone()).expect("spawn log writer");
    state.log_writer = log_writer;
    let state = Arc::new(state);

    let server = IpcServer::bind(&sock, state.clone()).expect("bind");

    // Accept two connections: RegisterRoot then DenyNotify.
    let h = thread::spawn(move || {
        server.accept_one().expect("accept RegisterRoot");
        server.accept_one().expect("accept DenyNotify");
    });

    // Register self so the daemon has a tracked node for our pid.
    register_self_as_tracked(&sock);

    // Build and send a DenyNotify frame.
    let self_pid = unsafe { libc::getpid() } as u32;
    let wire_token = AuditTokenWire {
        val: [0, 0, 0, 0, 0, self_pid, 0, 0],
    };
    let deny = DenyNotify::new(
        wire_token,
        Some("evil.example.com".into()),
        443,
        Some("93.184.216.34".into()),
        "connect",
        1_700_000_000_000,
    );

    let mut stream = UnixStream::connect(&sock).expect("connect DenyNotify");
    let ack = send_deny_notify_and_recv_ack(&mut stream, &deny);
    drop(stream);
    h.join().unwrap();

    // 1. Verify Ack
    match ack {
        DenyNotifyAck::Ok { schema_version } => {
            assert_eq!(schema_version, IPC_SCHEMA_V4);
        }
        other => panic!("expected DenyNotifyAck::Ok, got {:?}", other),
    }

    // 2. Give the writer thread a moment to flush.
    thread::sleep(std::time::Duration::from_millis(100));

    // 3. Verify blocks_today counter incremented.
    assert_eq!(
        state.log_writer.blocks_today.load(Ordering::Relaxed),
        1,
        "blocks_today must be 1 after one DenyNotify"
    );

    // 4. Read the JSONL file and verify the block row.
    let contents = std::fs::read_to_string(&log_path).expect("read log file");
    let lines: Vec<&str> = contents.lines().collect();
    assert_eq!(lines.len(), 1, "exactly one JSONL row");

    let row: serde_json::Value = serde_json::from_str(lines[0]).expect("parse JSONL row");
    assert_eq!(row["event"], "block");
    assert_eq!(row["verdict"], "Deny");
    assert_eq!(row["dest_host"], "evil.example.com");
    assert_eq!(row["dest_port"], 443);
    assert_eq!(row["dest_ip"], "93.184.216.34");
    assert_eq!(row["source_kind"], "hook_deny");
    assert_eq!(row["source_locator"], "connect");
}

#[test]
fn deny_notify_wrong_schema_version_returns_err() {
    let tmp = tempfile::tempdir().unwrap();
    ensure_state_dir(tmp.path()).unwrap();
    let sock = socket_path(tmp.path());

    let tree = Arc::new(ProcessTree::new());
    let det = Arc::new(GapDetector::new());
    let rs = Arc::new(RuleStore::open(&db_path(tmp.path())).expect("open rule store"));
    let curated = Arc::new(Vec::new());
    let state = Arc::new(DaemonState::new(
        tree,
        det,
        rs,
        curated,
        tmp.path().to_path_buf(),
    ));

    let server = IpcServer::bind(&sock, state).expect("bind");
    let h = thread::spawn(move || {
        server.accept_one().expect("accept DenyNotify");
    });

    // Send DenyNotify with wrong schema_version.
    let wire_token = AuditTokenWire {
        val: [0, 0, 0, 0, 0, 999, 0, 0],
    };
    let mut deny = DenyNotify::new(
        wire_token,
        Some("bad.example.com".into()),
        80,
        None,
        "sendto",
        0,
    );
    deny.schema_version = 9999; // wrong

    let mut stream = UnixStream::connect(&sock).expect("connect");
    let ack = send_deny_notify_and_recv_ack(&mut stream, &deny);
    drop(stream);
    h.join().unwrap();

    match ack {
        DenyNotifyAck::Err { message, .. } => {
            assert!(
                message.contains("schema_version"),
                "error message should mention schema_version: {message}"
            );
        }
        other => panic!("expected DenyNotifyAck::Err, got {:?}", other),
    }
}

#[test]
fn deny_notify_untracked_sender_still_logs() {
    let tmp = tempfile::tempdir().unwrap();
    ensure_state_dir(tmp.path()).unwrap();
    let sock = socket_path(tmp.path());
    let log_path = tmp.path().join("sentinel.log");

    let tree = Arc::new(ProcessTree::new());
    let det = Arc::new(GapDetector::new());
    let rs = Arc::new(RuleStore::open(&db_path(tmp.path())).expect("open rule store"));
    let curated = Arc::new(Vec::new());

    let mut state = DaemonState::new(
        tree,
        det,
        rs,
        curated,
        tmp.path().to_path_buf(),
    );
    state.log_writer = LogWriter::spawn(log_path.clone()).expect("spawn log writer");
    let state = Arc::new(state);

    let server = IpcServer::bind(&sock, state.clone()).expect("bind");

    // Only one accept — no RegisterRoot, so sender is untracked.
    let h = thread::spawn(move || {
        server.accept_one().expect("accept DenyNotify");
    });

    let wire_token = AuditTokenWire {
        val: [0, 0, 0, 0, 0, 12345, 0, 0],
    };
    let deny = DenyNotify::new(
        wire_token,
        Some("unknown-sender.example.com".into()),
        8080,
        None,
        "sendmsg",
        1_700_000_000_000,
    );

    let mut stream = UnixStream::connect(&sock).expect("connect");
    let ack = send_deny_notify_and_recv_ack(&mut stream, &deny);
    drop(stream);
    h.join().unwrap();

    // Should still succeed even for untracked senders.
    match ack {
        DenyNotifyAck::Ok { .. } => {}
        other => panic!("expected Ok even for untracked sender, got {:?}", other),
    }

    thread::sleep(std::time::Duration::from_millis(100));

    let contents = std::fs::read_to_string(&log_path).expect("read log file");
    let row: serde_json::Value =
        serde_json::from_str(contents.lines().next().expect("at least one line"))
            .expect("parse JSONL");
    assert_eq!(row["event"], "block");
    assert_eq!(row["source_kind"], "hook_deny");
    assert_eq!(row["dest_host"], "unknown-sender.example.com");
    // Untracked sender: run_uuid should be empty.
    assert_eq!(row["run_uuid"], "");
}
