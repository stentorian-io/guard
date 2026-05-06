//! Phase 3 plan 03-14 BLOCKER #3 / POL-02 acceptance — AllowOnce verdict.
//!
//! Test: sentinel run wraps curl against a non-allowlisted host (192.0.2.123,
//! RFC 5737 TEST-NET-1). The daemon parks the Resolve IPC because the process
//! is TTY-attached. The test sends "1\n" (AllowOnce) into the PTY. The daemon
//! resumes Resolve with Allow → curl can connect (or fail for unrelated reasons,
//! but NOT because Sentinel blocked it). A JSONL row with source_kind=prompt_allow_once
//! appears in sentinel.log.
//!
//! Marked #[ignore]: requires PTY (portable-pty) + non-hardened dylib + macOS
//! LaunchAgent path. Opt-in via:
//!   cargo test -p sentinel-e2e -- --ignored allow_once_unblocks

use std::io::{BufRead, BufReader, Write as _};
use std::time::{Duration, Instant};

use portable_pty::PtySize;

#[cfg(target_os = "macos")]
#[test]
#[ignore = "requires PTY + non-hardened dylib + macOS daemon — opt-in via --ignored"]
fn allow_once_unblocks_connection_in_live_run() {
    let harness = sentinel_e2e::DaemonHarness::start().expect("start daemon harness");
    let cli = sentinel_e2e::resolve_cli();
    let dylib = sentinel_e2e::resolve_dylib();

    let pty_system = portable_pty::native_pty_system();
    let pair = pty_system
        .openpty(PtySize { rows: 24, cols: 80, pixel_width: 0, pixel_height: 0 })
        .expect("openpty");

    let mut cmd = portable_pty::CommandBuilder::new(&cli);
    cmd.arg("run");
    cmd.arg("--");
    cmd.arg("/usr/bin/curl");
    cmd.arg("--max-time");
    cmd.arg("5");
    cmd.arg("https://192.0.2.123/");
    cmd.arg("-s");
    cmd.env("HOME", harness.home.path().to_str().unwrap());
    cmd.env(
        "PATH",
        std::env::var("PATH").unwrap_or_default().as_str(),
    );
    cmd.env("SENTINEL_HOOK_DYLIB", dylib.to_str().unwrap());
    cmd.env(
        "SENTINEL_STATE_DIR",
        harness.state_dir.to_str().unwrap(),
    );

    let mut child = pair.slave.spawn_command(cmd).expect("spawn sentinel run");
    let reader = pair.master.try_clone_reader().expect("clone reader");
    let mut writer = pair.master.take_writer().expect("take writer");
    drop(pair.slave);

    // Wait for the prompt to appear ("Choose: [1]" text from prompt_render.rs).
    let mut br = BufReader::new(reader);
    let mut buf = String::new();
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if Instant::now() > deadline {
            panic!("prompt never appeared in PTY output within 10s; buf so far: {buf}");
        }
        let mut line = String::new();
        match br.read_line(&mut line) {
            Ok(0) | Err(_) => break,
            Ok(_) => {}
        }
        buf.push_str(&line);
        if buf.contains("Choose: [1]") {
            break;
        }
    }

    // Send AllowOnce choice.
    writer.write_all(b"1\n").expect("write choice 1");
    drop(writer);

    let _ = child.wait();
    std::thread::sleep(Duration::from_millis(500));

    // Assert: JSONL log has a prompt_allow_once row.
    let log = harness
        .home
        .path()
        .join("Library/Logs/Sentinel/sentinel.log");
    let content = std::fs::read_to_string(&log).unwrap_or_default();
    assert!(
        content.lines().any(|l| {
            l.contains(r#""source_kind":"prompt_allow_once""#)
                || l.contains(r#""source_kind": "prompt_allow_once""#)
        }),
        "no prompt_allow_once row found in JSONL;\ncontent: {content}"
    );
}
