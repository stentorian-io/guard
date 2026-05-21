//! M004-S01 T06: E2E test verifying the watchdog detects daemon death
//! and that the daemon's Ping handler responds correctly when alive.
//!
//! Flow:
//! 1. Start daemon via DaemonHarness
//! 2. Verify IPC Ping returns Pong (daemon alive)
//! 3. Kill daemon with SIGKILL
//! 4. Verify IPC Ping returns Unreachable (daemon dead)

use guard_e2e::DaemonHarness;
use guard_ipc::frame::{read_frame, write_frame};
use guard_ipc::{Ping, PingReply};
use socket2::{Domain, SockAddr, Socket, Type};
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::time::Duration;

const TAG_PING: u8 = 0x15;

fn ping_daemon(sock: &Path) -> Option<(u32, u64)> {
    let addr = SockAddr::unix(sock).ok()?;
    let socket = Socket::new(Domain::UNIX, Type::STREAM, None).ok()?;
    socket
        .connect_timeout(&addr, Duration::from_millis(500))
        .ok()?;
    socket
        .set_read_timeout(Some(Duration::from_millis(500)))
        .ok();
    socket
        .set_write_timeout(Some(Duration::from_millis(500)))
        .ok();
    let mut stream: UnixStream = socket.into();
    stream.write_all(&[TAG_PING]).ok()?;
    let req = Ping::new();
    write_frame(&mut stream, &req).ok()?;
    let mut tag_back = [0u8; 1];
    stream.read_exact(&mut tag_back).ok()?;
    if tag_back[0] != TAG_PING {
        return None;
    }
    let reply: PingReply = read_frame(&mut stream).ok()?;
    match reply {
        PingReply::Pong {
            pid, uptime_secs, ..
        } => Some((pid, uptime_secs)),
        PingReply::Err { .. } => None,
    }
}

#[test]
fn watchdog_detects_daemon_alive_then_dead() {
    let harness = DaemonHarness::start().expect("start daemon");

    // Step 1: Daemon is alive — Ping must return Pong
    let result = ping_daemon(&harness.socket);
    assert!(result.is_some(), "expected Pong from live daemon, got None");
    let (pid, uptime) = result.unwrap();
    assert!(pid > 0, "daemon pid must be positive");
    // Uptime should be very small (just started)
    assert!(uptime < 10, "daemon uptime unexpectedly high: {uptime}s");

    // Step 2: Kill daemon with SIGKILL
    let daemon_pid = harness.child.id() as libc::pid_t;
    unsafe {
        libc::kill(daemon_pid, libc::SIGKILL);
    }
    std::thread::sleep(Duration::from_millis(100));

    // Step 3: Daemon is dead — Ping must return None (unreachable)
    let result_after_kill = ping_daemon(&harness.socket);
    assert!(
        result_after_kill.is_none(),
        "expected None from dead daemon, got: {result_after_kill:?}"
    );
}

#[test]
fn ping_nonexistent_socket_returns_none() {
    let dir = tempfile::tempdir().unwrap();
    let sock = dir.path().join("no-such.sock");
    assert!(ping_daemon(&sock).is_none());
}
