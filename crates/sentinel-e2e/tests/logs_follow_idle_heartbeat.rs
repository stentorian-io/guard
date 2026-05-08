//! Phase 3 plan 03-19 (gap closure for UAT item #4) — `sentinel logs --follow`
//! survives a 6-second idle period without dying. The watcher's
//! recv_timeout(1s) heartbeat keeps the process responsive indefinitely.

use std::io::Write as _;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

#[cfg(target_os = "macos")]
#[test]
#[ignore = "wall-clock heavy (6+ s idle); opt-in via --ignored"]
fn follow_survives_6s_idle_then_resumes_streaming() {
    let harness = sentinel_e2e::DaemonHarness::start().expect("start daemon");
    let cli = sentinel_e2e::resolve_cli();
    let log_dir = harness.home.path().join("Library/Logs/Sentinel");
    std::fs::create_dir_all(&log_dir).expect("create log_dir");
    let log_path = log_dir.join("sentinel.log");
    // Touch sentinel.log so --follow has something to subscribe to.
    std::fs::write(&log_path, b"").expect("touch log");

    // Phase 07 plan 05 (D-09, D-10): `logs --follow` → `status logs --follow`.
    let mut follow = Command::new(&cli)
        .arg("status")
        .arg("logs")
        .arg("--follow")
        .env_clear()
        .env("HOME", harness.home.path())
        .env("PATH", std::env::var_os("PATH").unwrap_or_default())
        .env("SENTINEL_STATE_DIR", &harness.state_dir)
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn follow");
    std::thread::sleep(Duration::from_millis(500));

    // Idle for 6 seconds — no log activity at all.
    std::thread::sleep(Duration::from_secs(6));

    // Assert process still alive after the idle gap.
    match follow.try_wait().expect("try_wait") {
        None => {} // alive — good
        Some(status) => {
            panic!(
                "--follow exited during idle period (status: {status:?}); \
                 watcher heartbeat broken"
            );
        }
    }

    // Append a row directly to sentinel.log (bypassing daemon — direct append).
    let marker_row =
        r#"{"event":"allow","ts":"2026-05-08T12:00:00.000Z","dest_host":"post_idle_marker"}"#;
    {
        let mut f = std::fs::OpenOptions::new()
            .append(true)
            .open(&log_path)
            .expect("open append");
        writeln!(f, "{marker_row}").expect("write");
    }

    // Wait up to 3 seconds for --follow to pick up the marker row.
    // Since we can't do non-blocking stdout reads here without extra threads,
    // we give --follow a bit of time to pick it up, then kill and collect.
    let deadline = Instant::now() + Duration::from_secs(3);
    while Instant::now() < deadline {
        // Re-check that follow is still alive.
        if follow.try_wait().expect("try_wait").is_some() {
            break;
        }
        std::thread::sleep(Duration::from_millis(200));
    }

    // Kill and collect.
    let _ = follow.kill();
    let out = follow.wait_with_output().expect("wait follow");
    let accumulated = String::from_utf8_lossy(&out.stdout).into_owned();

    assert!(
        accumulated.contains("post_idle_marker"),
        "post-idle marker did not appear in --follow stdout; \
         captured: {}",
        &accumulated.chars().take(2000).collect::<String>()
    );
}
