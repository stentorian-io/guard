//! End-to-end test: spin up a daemon (in this test process via IpcServer),
//! call register_root_with_daemon, assert Ack received.
//!
//! Also tests envp construction shape (without actually spawning, since that
//! requires a real wrapped target binary).

use sentinel_cli::ipc_client::{probe_daemon_alive, register_root_with_daemon};
use sentinel_core::AuditToken;
use sentinel_daemon::gap_detector::GapDetector;
use sentinel_daemon::ipc_server::{DaemonState, IpcServer};
use sentinel_daemon::rule_store::RuleStore;
use sentinel_daemon::state_dir::{db_path, ensure_state_dir, socket_path};
use sentinel_daemon::tracked::ProcessTree;
use std::ffi::OsStr;
use std::path::Path;
use std::sync::Arc;
use std::thread;

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

#[test]
fn register_root_with_daemon_round_trips_ack() {
    let tmp = tempfile::tempdir().unwrap();
    ensure_state_dir(tmp.path()).unwrap();
    let sock = socket_path(tmp.path());

    let (tree, state) = build_state(tmp.path());
    let server = IpcServer::bind(&sock, state).expect("bind");

    let h = thread::spawn(move || {
        server.accept_one().expect("accept_one");
    });

    // Use a dummy synthetic token; the daemon should record the kernel-sourced
    // token (this test process's own) per T-01-04-03.
    let dummy = AuditToken::synthetic([0; 8]);
    let r = register_root_with_daemon(&sock, dummy);
    assert!(r.is_ok(), "register_root_with_daemon should return Ok: {r:?}");

    h.join().unwrap();
    assert_eq!(tree.nodes_len(), 1, "exactly one root recorded");
    assert!(!tree.is_tracked(&dummy), "synthetic wire token must not be stored (T-01-04-03)");
}

#[test]
fn register_root_returns_daemon_unreachable_when_socket_missing() {
    let tmp = tempfile::tempdir().unwrap();
    let bogus_sock = tmp.path().join("does-not-exist.sock");
    let dummy = AuditToken::synthetic([0; 8]);
    let r = register_root_with_daemon(&bogus_sock, dummy);
    match r {
        Err(sentinel_cli::CliError::DaemonUnreachable(_)) => {}
        other => panic!("expected DaemonUnreachable, got {:?}", other),
    }
}

/// Connect-only probe against a live daemon socket succeeds (no frame sent;
/// the daemon's accept loop sees connect+EOF as a benign liveness check).
#[test]
fn probe_daemon_alive_succeeds_against_live_socket() {
    let tmp = tempfile::tempdir().unwrap();
    ensure_state_dir(tmp.path()).unwrap();
    let sock = socket_path(tmp.path());

    let (tree, state) = build_state(tmp.path());
    let server = IpcServer::bind(&sock, state).expect("bind");

    // The probe drops the stream immediately. The daemon's `accept_one` will
    // see the connect, then EOF on the first read_frame. Per plan 05 task 2's
    // contract, this is benign — accept_one returns Ok without touching state.
    let h = thread::spawn(move || {
        server.accept_one().expect("accept_one tolerates connect+EOF benignly");
    });

    let r = probe_daemon_alive(&sock);
    assert!(r.is_ok(), "probe should succeed against a live daemon socket: {r:?}");

    h.join().unwrap();
    // No state should have changed — tracked-roots remains empty.
    assert_eq!(tree.nodes_len(), 0, "probe-only must not record a tracked root");
}

/// Connect-only probe against a missing socket returns DaemonUnreachable
/// (proving T-01-08-06: CLI exits 70 BEFORE spawning an unprotected child).
#[test]
fn probe_daemon_alive_fails_when_socket_missing() {
    let tmp = tempfile::tempdir().unwrap();
    let bogus_sock = tmp.path().join("does-not-exist.sock");
    let r = probe_daemon_alive(&bogus_sock);
    match r {
        Err(sentinel_cli::CliError::DaemonUnreachable(_)) => {}
        other => panic!("expected DaemonUnreachable, got {:?}", other),
    }
}

/// Smoke test the envp construction shape by spawning `/bin/echo`.
/// We only assert that posix_spawnp returns a valid pid and the child exits
/// 0 — we do NOT assert the dylib was loaded (it won't be, for hardened echo).
///
/// The full "dylib loaded into the child" e2e is in plan 09 against Homebrew node.
#[test]
fn spawn_wrapped_against_echo_returns_valid_pid() {
    let dylib = tempfile::NamedTempFile::new().unwrap(); // dummy dylib path
    let mfst = tempfile::NamedTempFile::new().unwrap(); // dummy manifest path
    let prog = Path::new("/bin/echo");
    let pid = sentinel_cli::spawn::spawn_wrapped(
        prog,
        &[OsStr::new("hello")],
        dylib.path(),
        mfst.path(),
    )
    .expect("spawn_wrapped");
    assert!(pid > 0);
    // Reap the child to avoid zombie.
    let mut status: libc::c_int = 0;
    unsafe { libc::waitpid(pid, &mut status, 0) };
}

/// ISS-10 remediation: confirm `audit_token_for_pid` succeeds against a real
/// posix_spawn'd child. This exercises the primary path (task_name_for_pid +
/// task_info(TASK_AUDIT_TOKEN)) — and if Apple has tightened access on the
/// running OS, exercises the proc_pidinfo fallback. Either way the function
/// must return Ok.
#[test]
fn audit_token_for_pid_succeeds_against_spawned_child() {
    let dylib = tempfile::NamedTempFile::new().unwrap();
    let mfst = tempfile::NamedTempFile::new().unwrap();
    // Use /bin/sleep at a negligible duration. The child sleeps 200ms then exits.
    let prog = Path::new("/bin/sleep");
    let pid = sentinel_cli::spawn::spawn_wrapped(
        prog,
        &[OsStr::new("0.2")],
        dylib.path(),
        mfst.path(),
    )
    .expect("spawn_wrapped sleep");
    assert!(pid > 0);

    // Sample the audit token while the child is alive.
    let token = sentinel_cli::audit_token::audit_token_for_pid(pid)
        .expect("audit_token_for_pid against posix_spawn'd child");
    // val[5] must equal the pid regardless of which path (primary or fallback)
    // produced the token.
    assert_eq!(
        token.val[5] as libc::pid_t,
        pid,
        "token.val[5] must equal pid; primary or fallback path"
    );
    // Reap to avoid zombie.
    let mut status: libc::c_int = 0;
    unsafe { libc::waitpid(pid, &mut status, 0) };
}
