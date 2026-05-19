// crates/sentinel-hook/tests/daemon_dead_socket_returns_io_error.rs
//
// v0.7 / VAL-05 D-38 verification spike.
//
// Proves that the existing RESOLVE_TIMEOUT_MS=100 + connect_with_timeout shape in
// crates/sentinel-hook/src/ipc_client.rs returns deterministically (and well under
// node's 4s deadline) when the Unix socket file persists on disk but has no
// listener — the SIGKILL'd-daemon scenario per RESEARCH §Pitfall 5.
//
// If this test PASSES (default expectation), the D-40 contingency dylib changes
// in ipc_client.rs are NOT needed — the failure_modes_daemon_killed
// lenient/strict split can collapse to denied-only without further dylib edits.
//
// If this test FAILS, the D-40 fast-path must be added:
// detect ECONNREFUSED / ENOENT inside connect_with_timeout and return an
// IpcClientError variant that maps to the cache-miss-deny path.

use sentinel_hook::ipc_client::{
    _clear_daemon_socket_for_test, _set_daemon_socket_for_test, send_resolve_sync, IpcClientError,
};
use std::os::unix::net::UnixListener;
use std::time::Instant;

// Serialize the two #[test] fns in THIS binary — they both mutate the
// process-global TEST_SOCKET_OVERRIDE via _set_daemon_socket_for_test
// and would race under cargo test's default thread parallelism.
// Cross-binary serialization is not required: each tests/*.rs is a
// separate integration-test binary in its own process, so they each
// see their own copy of TEST_SOCKET_OVERRIDE.
static SOCKET_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

#[cfg_attr(not(target_os = "macos"), ignore)]
#[test]
fn dead_socket_returns_io_error_immediately() {
    let _lock = SOCKET_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());

    let dir = tempfile::tempdir().expect("tempdir");
    let sock_path = dir.path().join("dead_resolver.sock");

    // Create the listener so the socket file exists, then drop it. After drop,
    // the file persists on disk (macOS does not unlink on close) but no
    // listener is bound — connect() will ECONNREFUSED.
    {
        let listener = UnixListener::bind(&sock_path).expect("bind unix listener");
        drop(listener);
    }
    assert!(
        sock_path.exists(),
        "socket file must persist after listener drop (mirrors SIGKILL daemon, RESEARCH §Pitfall 5)"
    );

    _set_daemon_socket_for_test(sock_path.clone());

    let t0 = Instant::now();
    let result = send_resolve_sync("registry.npmjs.org", 443, 100);
    let dt = t0.elapsed();

    _clear_daemon_socket_for_test();

    // Deterministic shape: ECONNREFUSED bubbles up as IpcClientError::Io with
    // ErrorKind::ConnectionRefused.
    match &result {
        Err(IpcClientError::Io(e)) if e.kind() == std::io::ErrorKind::ConnectionRefused => {}
        other => panic!(
            "VAL-05 D-38: expected Err(IpcClientError::Io(ConnectionRefused)); got {other:?} \
             after {dt:?}"
        ),
    }

    // Bounded latency: ECONNREFUSED is instant; we must finish well under the
    // 100ms timeout. Allow some slack for slow CI but stay far below node's 4s
    // deadline.
    assert!(
        dt.as_millis() < 50,
        "VAL-05 D-38: ECONNREFUSED must return immediately; observed {dt:?} \
         (full resolve walk of 4 attempts must complete << 4s)"
    );
}

#[cfg_attr(not(target_os = "macos"), ignore)]
#[test]
fn dead_socket_full_resolve_walk_completes_under_node_deadline() {
    let _lock = SOCKET_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());

    let dir = tempfile::tempdir().expect("tempdir");
    let sock_path = dir.path().join("dead_resolver.sock");
    {
        let listener = UnixListener::bind(&sock_path).expect("bind");
        drop(listener);
    }
    _set_daemon_socket_for_test(sock_path.clone());

    // Mirror replace_libc.rs:23 MAX_RESOLVE_ATTEMPTS = 4 — four sequential
    // attempts is the worst-case shape the libc hot path executes when the
    // daemon dies mid-run.
    let t0 = Instant::now();
    for _ in 0..4 {
        let _ = send_resolve_sync("registry.npmjs.org", 443, 100);
    }
    let dt = t0.elapsed();

    _clear_daemon_socket_for_test();

    // Node's wrapped child has a 4s deadline; even a generous bound of 200ms
    // for four ECONNREFUSED-instant returns is comfortable.
    assert!(
        dt.as_millis() < 200,
        "VAL-05 D-38: full 4-attempt resolve walk against dead socket must complete \
         well under node's 4s deadline; observed {dt:?}"
    );
}
