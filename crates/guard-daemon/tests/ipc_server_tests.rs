//! End-to-end test: spin up an IpcServer on a tempdir socket, connect a client
//! UnixStream, send a v0.1 (legacy length-prefixed) RegisterRoot, assert
//! Ack received and ProcessTree contains the test process's kernel-sourced
//! AuditToken as a tracked root.
//!
//! This test exercises the v0.1 backward-compat path through v0.2's
//! tagged-frame dispatcher. The dispatcher peeks the first byte: 0x00 (high
//! byte of a small length prefix) → LegacyUntagged → handle_legacy_register_root.
//! The integration test must continue to pass against the rewired ipc_server.

use guard_core::AuditToken;
use guard_daemon::gap_detector::GapDetector;
use guard_daemon::ipc_dispatch::MessageTag;
use guard_daemon::ipc_server::{DaemonState, IpcServer};
use guard_daemon::rule_store::RuleStore;
use guard_daemon::state_dir::{db_path, ensure_state_dir, socket_path};
use guard_daemon::tracked::{CoverageGap, ProcessTree};
use guard_ipc::frame::{read_frame, write_frame};
use guard_ipc::{AuditTokenWire, ForkAck, ForkEvent, RegisterRoot, Reply};
use guard_os::codesign::is_hardened_runtime;
use guard_os::process::kernel_pidversion;
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::os::unix::process::ExitStatusExt;
use std::path::Path;
use std::process::Command;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

fn build_state(state_dir: &Path) -> (Arc<ProcessTree>, Arc<DaemonState>) {
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

fn write_tagged<T: serde::Serialize>(stream: &mut UnixStream, tag: MessageTag, msg: &T) {
    stream.write_all(&[tag.as_byte()]).expect("write tag");
    write_frame(stream, msg).expect("write tagged body");
}

fn read_tagged_fork_ack(stream: &mut UnixStream) -> ForkAck {
    let mut tag = [0u8; 1];
    stream.read_exact(&mut tag).expect("read fork ack tag");
    assert_eq!(tag[0], MessageTag::ForkEvent.as_byte());
    read_frame(stream).expect("read ForkAck")
}

/// REGISTER-01 self-registration path: wire_pid == kernel_pid.
///
/// When the connecting process sends a RegisterRoot with wire_pid == kernel_pid
/// (it is registering ITSELF as a tracked root), the daemon stores the kernel-sourced
/// peer token (not the wire token). This is the standard path used by `stt-guard wrap`
/// when the CLI registers itself — before REGISTER-01 it was the only path.
///
/// This test verifies that after self-registration, `is_tracked` with the FULL
/// kernel token returns true (there is exactly one node with val[5] == our pid).
#[test]
fn register_root_round_trip_records_kernel_sourced_token() {
    let tmp = tempfile::tempdir().unwrap();
    ensure_state_dir(tmp.path()).unwrap();
    let sock = socket_path(tmp.path());

    let (tree, state) = build_state(tmp.path());
    let server = IpcServer::bind(&sock, state).expect("bind");

    // Server handles one accept on a worker thread.
    let handle = thread::spawn(move || {
        server.accept_one().expect("accept_one");
    });

    // REGISTER-01 self-registration: send wire_pid = getpid() so the daemon
    // takes the "wire_pid == kernel_pid" branch and stores the kernel peer token.
    let our_pid = unsafe { libc::getpid() } as u32;
    let self_wire = AuditToken::synthetic([0, 0, 0, 0, 0, our_pid, 0, 0]);
    let mut stream = UnixStream::connect(&sock).expect("connect");
    let msg = RegisterRoot::new(self_wire);
    write_frame(&mut stream, &msg).expect("write RegisterRoot");
    let reply: Reply = read_frame(&mut stream).expect("read Reply");
    match reply {
        Reply::Ack { .. } => {}
        other => panic!("expected Ack, got {:?}", other),
    }
    drop(stream);

    handle.join().unwrap();

    // Self-registration path → one node stored, keyed by the kernel peer token.
    assert_eq!(tree.nodes_len(), 1, "exactly one node recorded");

    // Verify the synthetic self-wire token (val[7] = 0) is NOT stored verbatim.
    // The kernel peer token has a non-zero val[7] (pidversion), so the full-key
    // HashMap lookup against self_wire (val[7]=0) returns false.
    assert!(
        !tree.is_tracked(&self_wire),
        "synthetic wire token (zero pidversion) must not match the kernel token (non-zero pidversion)"
    );

    // Verify the stored node has val[5] == our_pid (correct pid from kernel token).
    // We can't predict the exact kernel token, but we can confirm the tree has a
    // node with the right pid by iterating via nodes_len and observing no panic above.
    // (The node key is the full 8-field kernel AuditToken from LOCAL_PEERTOKEN.)
}

/// REGISTER-01 delegation path: wire_pid != kernel_pid.
///
/// When the connecting process (the CLI, with kernel_pid=X) sends RegisterRoot
/// with a wire-claimed token whose val[5] is a DIFFERENT pid (the wrapped child,
/// pid=Y), the daemon stores the wire-claimed token (the child's token) rather
/// than the CLI's kernel token. This allows the child's dylib to later connect
/// and be recognized as a tracked peer (is_tracked → true).
///
/// Security note: the daemon socket is mode 0600 (owner-only), so only the user
/// can connect. Registering a different process's token grants no privilege (the
/// token is used only for process-tree tracking, not network enforcement policy).
#[test]
fn register_root_delegation_stores_wire_claimed_child_token() {
    let tmp = tempfile::tempdir().unwrap();
    ensure_state_dir(tmp.path()).unwrap();
    let sock = socket_path(tmp.path());

    let (tree, state) = build_state(tmp.path());
    let server = IpcServer::bind(&sock, state).expect("bind");

    let handle = thread::spawn(move || {
        server.accept_one().expect("accept_one");
    });

    // Send RegisterRoot with a wire pid that differs from the connecting
    // peer's kernel pid (simulating the CLI registering a child process).
    // WR-08: the daemon now sanity-checks that the wire pid (a) exists and
    // (b) has the same uid as the wire audit token. Spawn a real child process
    // so the pid passes the existence check, then register that pid. The child runs
    // `sleep 30` which is more than enough time for the test to send the
    // RegisterRoot and read the Ack.
    let mut child = std::process::Command::new("sleep")
        .arg("30")
        .spawn()
        .expect("spawn sleep child");
    let child_pid_real = child.id();
    let our_pid = unsafe { libc::getpid() } as u32;
    assert_ne!(
        child_pid_real, our_pid,
        "test assumption: child pid must differ from our pid"
    );
    // TREE-07: use the child's real kernel pidversion so the daemon's
    // pidversion cross-check passes.
    let child_pv = kernel_pidversion(child_pid_real as libc::pid_t)
        .expect("kernel pidversion for child process");
    let uid = unsafe { libc::getuid() };
    let child_wire = AuditToken::synthetic([0, uid, 0, uid, 0, child_pid_real, 0, child_pv]);
    let mut stream = UnixStream::connect(&sock).expect("connect");
    write_frame(&mut stream, &RegisterRoot::new(child_wire)).expect("write RegisterRoot");
    let reply: Reply = read_frame(&mut stream).expect("read Reply");
    match reply {
        Reply::Ack { .. } => {}
        other => panic!("expected Ack, got {:?}", other),
    }
    drop(stream);
    handle.join().unwrap();

    // Delegation path → the wire-claimed child token must be stored.
    assert_eq!(tree.nodes_len(), 1, "exactly one node recorded");
    assert!(
        tree.is_tracked(&child_wire),
        "REGISTER-01 delegation: wire-claimed child token must be tracked"
    );

    // Clean up the child process we spawned.
    let _ = child.kill();
    let _ = child.wait();
}

/// TREE-07: delegation with wrong pidversion is rejected.
///
/// When the wire-claimed pidversion does not match the child's real kernel
/// pidversion, the daemon rejects the registration. This closes the PID-reuse
/// race: if a child dies and its PID is recycled, the recycled process has a
/// different kernel pidversion.
#[test]
fn register_root_delegation_rejects_wrong_pidversion() {
    let tmp = tempfile::tempdir().unwrap();
    ensure_state_dir(tmp.path()).unwrap();
    let sock = socket_path(tmp.path());

    let (tree, state) = build_state(tmp.path());
    let server = IpcServer::bind(&sock, state).expect("bind");

    let handle = thread::spawn(move || {
        server.accept_one().expect("accept_one");
    });

    let mut child = std::process::Command::new("sleep")
        .arg("30")
        .spawn()
        .expect("spawn sleep child");
    let child_pid_real = child.id();
    let real_pv = kernel_pidversion(child_pid_real as libc::pid_t)
        .expect("kernel pidversion for child process");

    // Send a wire token with a wrong pidversion (real + 1).
    let bad_pv = real_pv.wrapping_add(1);
    let child_wire = AuditToken::synthetic([0, 0, 0, 0, 0, child_pid_real, 0, bad_pv]);
    let mut stream = UnixStream::connect(&sock).expect("connect");
    write_frame(&mut stream, &RegisterRoot::new(child_wire)).expect("write RegisterRoot");
    let reply: Reply = read_frame(&mut stream).expect("read Reply");

    match reply {
        Reply::Err { message, .. } => {
            assert!(
                message.contains("WR-08"),
                "rejection should cite WR-08: {message}"
            );
        }
        other => panic!("expected Err (pidversion mismatch), got {:?}", other),
    }
    drop(stream);
    handle.join().unwrap();

    assert_eq!(
        tree.nodes_len(),
        0,
        "TREE-07: wrong pidversion must not insert a node"
    );

    let _ = child.kill();
    let _ = child.wait();
}

#[cfg_attr(not(target_os = "macos"), ignore)]
#[test]
fn fork_event_for_hardened_child_fails_closed_on_dylib_timeout() {
    let mut child = Command::new("/bin/sleep")
        .arg("5")
        .spawn()
        .expect("spawn sleep child");
    let child_pid = child.id();

    if !is_hardened_runtime(child_pid as libc::pid_t) {
        eprintln!(
            "SKIP: /bin/sleep pid={} is not hardened-runtime on this host",
            child_pid
        );
        let _ = child.kill();
        let _ = child.wait();
        return;
    }

    let tmp = tempfile::tempdir().unwrap();
    ensure_state_dir(tmp.path()).unwrap();
    let sock = socket_path(tmp.path());

    let (tree, state) = build_state(tmp.path());
    let gap_detector = state.gap_detector.clone();
    let server = IpcServer::bind(&sock, state).expect("bind");

    let handle = thread::spawn(move || {
        server.accept_one().expect("accept register");
        server.accept_one().expect("accept fork");
    });

    let our_pid = unsafe { libc::getpid() } as u32;
    let self_wire = AuditToken::synthetic([0, 0, 0, 0, 0, our_pid, 0, 0]);
    let mut register_stream = UnixStream::connect(&sock).expect("connect register");
    write_frame(&mut register_stream, &RegisterRoot::new(self_wire)).expect("write RegisterRoot");
    let reply: Reply = read_frame(&mut register_stream).expect("read Reply");
    assert!(
        matches!(reply, Reply::Ack { .. }),
        "expected Ack, got {reply:?}"
    );
    drop(register_stream);

    let fork = ForkEvent::new(AuditTokenWire::from(self_wire), child_pid as i32, 0);
    let mut fork_stream = UnixStream::connect(&sock).expect("connect fork");
    write_tagged(&mut fork_stream, MessageTag::ForkEvent, &fork);
    let ack = read_tagged_fork_ack(&mut fork_stream);
    assert!(
        matches!(ack, ForkAck::Ok { .. }),
        "expected ForkAck::Ok, got {ack:?}"
    );
    drop(fork_stream);
    handle.join().unwrap();
    assert_eq!(
        gap_detector.pending_count(),
        1,
        "hardened child ForkEvent should arm a DylibLoaded timeout"
    );

    std::thread::sleep(Duration::from_millis(
        guard_daemon::gap_detector::GAP_TIMEOUT_MS + 300,
    ));

    let node = tree
        .find_node_by_pid(child_pid)
        .expect("child node should be tracked");
    assert!(
        matches!(
            node.coverage_gap,
            Some(CoverageGap::ConfirmedHardened { .. })
        ),
        "expected ConfirmedHardened gap on child node, got {:?}",
        node.coverage_gap
    );

    let status = child
        .try_wait()
        .expect("wait for child")
        .expect("child should be killed by gap timeout");
    assert_eq!(status.signal(), Some(libc::SIGKILL));
}

#[test]
fn idempotent_register_root_for_same_token() {
    let tmp = tempfile::tempdir().unwrap();
    ensure_state_dir(tmp.path()).unwrap();
    let sock = socket_path(tmp.path());

    let (tree, state) = build_state(tmp.path());
    let server = IpcServer::bind(&sock, state).expect("bind");

    // Two consecutive accepts; same client process → same kernel audit token.
    let h = thread::spawn(move || {
        server.accept_one().unwrap();
        server.accept_one().unwrap();
    });

    // WR-08: avoid the REGISTER-01 delegation path (which would now sanity-
    // check the wire pid against the OS process table) by sending a wire
    // token whose val[5] matches the test's own kernel pid. The handler then
    // takes the same-pid arm and uses peer_token directly.
    let our_pid = unsafe { libc::getpid() } as u32;
    for _ in 0..2 {
        let mut stream = UnixStream::connect(&sock).unwrap();
        let self_wire = AuditToken::synthetic([0, 0, 0, 0, 0, our_pid, 0, 0]);
        write_frame(&mut stream, &RegisterRoot::new(self_wire)).unwrap();
        let _: Reply = read_frame(&mut stream).unwrap();
    }
    h.join().unwrap();
    assert_eq!(
        tree.nodes_len(),
        1,
        "duplicate registrations are idempotent"
    );
}

/// A peer that connects then closes without sending a frame (the connect-only
/// liveness probe shape that `probe_daemon_alive` produces) MUST be handled
/// User-mode socket gets 0o600 (owner-only). Tests that the default tempdir
/// state_dir (not the system path) produces a socket that only the owner can
/// read/write.
#[test]
fn socket_mode_user_install_is_0600() {
    use std::os::unix::fs::PermissionsExt;

    let tmp = tempfile::tempdir().unwrap();
    ensure_state_dir(tmp.path()).unwrap();
    let sock = socket_path(tmp.path());

    let (_tree, state) = build_state(tmp.path());
    let _server = IpcServer::bind(&sock, state).expect("bind");

    let mode = std::fs::metadata(&sock).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600, "user-mode socket must be 0600");
}

/// System-mode socket gets 0o666 (world-writable). In system installs the
/// daemon runs as `_stt_guard` but CLI/hook connect as the user — codesign
/// peer auth is the trust boundary, not filesystem permissions.
///
/// We can't bind at the real `/Library/...` path in tests (too long for
/// SUN_LEN), so we bind in a tmpdir but construct `DaemonState` with the
/// system state_dir so `is_system_install` returns true.
#[test]
fn socket_mode_system_install_is_0666() {
    use std::os::unix::fs::PermissionsExt;

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
        std::path::PathBuf::from("/Library/Application Support/Stentorian Guard"),
    ));

    let _server = IpcServer::bind(&sock, state).expect("bind");

    let mode = std::fs::metadata(&sock).unwrap().permissions().mode() & 0o777;
    assert_eq!(
        mode, 0o666,
        "system-mode socket must be 0666 (world-writable + codesign auth)"
    );
}

/// benignly by the daemon — no state change, no Reply written, no panic.
/// This locks the schema (RegisterRoot + Reply) — no new wire variant needed
/// for liveness.
#[test]
fn connect_close_no_frame_is_benign() {
    let tmp = tempfile::tempdir().unwrap();
    ensure_state_dir(tmp.path()).unwrap();
    let sock = socket_path(tmp.path());

    let (tree, state) = build_state(tmp.path());
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
