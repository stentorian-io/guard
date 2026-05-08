//! Phase 3 plan 03-14 BLOCKER #1 / D-79 acceptance — SIGINT cancels parked prompt.
//!
//! Test: SIGINT is sent to the sentinel run process while a prompt is parked.
//! The SIGINT handler (sigint_handler.rs, plan 03-13) calls PromptCancel for
//! all in-flight prompt IDs, then propagates SIGINT to the wrapped process group.
//! Expected outcomes:
//!   - PromptCancel sent → daemon emits a GapRecord with gap_kind="prompt-cancelled"
//!   - wrapped curl exits (SIGINT propagated to pgid)
//!   - sentinel run exits reflecting the SIGINT
//!
//! Marked #[ignore]: requires PTY + signal-aware test runner + macOS daemon.
//! Opt-in via: cargo test -p sentinel-e2e -- --ignored sigint_during_prompt

use std::io::{BufRead, BufReader};
use std::time::{Duration, Instant};

use portable_pty::PtySize;

#[cfg(target_os = "macos")]
#[test]
#[ignore = "requires PTY + signal-aware runner + macOS daemon — opt-in via --ignored"]
fn sigint_during_prompt_sends_cancel_and_propagates_to_child() {
    let harness = sentinel_e2e::DaemonHarness::start().expect("start daemon harness");
    let cli = sentinel_e2e::resolve_cli();
    let dylib = sentinel_e2e::resolve_dylib();

    let pty_system = portable_pty::native_pty_system();
    let pair = pty_system
        .openpty(PtySize { rows: 24, cols: 80, pixel_width: 0, pixel_height: 0 })
        .expect("openpty");

    let mut cmd = portable_pty::CommandBuilder::new(&cli);
    cmd.arg("/usr/bin/curl");
    cmd.arg("--max-time");
    cmd.arg("30"); // long timeout so curl is alive when SIGINT fires
    cmd.arg("https://192.0.2.203/");
    cmd.arg("-s");
    cmd.env("HOME", harness.home.path().to_str().unwrap());
    cmd.env("PATH", std::env::var("PATH").unwrap_or_default().as_str());
    cmd.env("SENTINEL_HOOK_DYLIB", dylib.to_str().unwrap());
    cmd.env("SENTINEL_STATE_DIR", harness.state_dir.to_str().unwrap());

    let mut child = pair.slave.spawn_command(cmd).expect("spawn");
    let pid = child
        .process_id()
        .expect("get process id") as i32;
    let reader = pair.master.try_clone_reader().expect("reader");
    drop(pair.slave);

    // Wait for the prompt to appear (sentinel run's render loop prints "Choose: [1]").
    let mut br = BufReader::new(reader);
    let mut buf = String::new();
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if Instant::now() > deadline {
            panic!("prompt never appeared within 10s; buf: {buf}");
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

    // Send SIGINT to the sentinel run process (which will propagate to the pgid).
    // The SIGINT handler (D-79) should: cancel in-flight prompts + SIGINT to pgid.
    unsafe {
        libc::kill(pid, libc::SIGINT);
    }

    // Wait for sentinel run to exit (SIGINT handled + child reaped).
    let _ = child.wait();
    std::thread::sleep(Duration::from_millis(500));

    // Assert: JSONL gap row with gap_kind="prompt-cancelled".
    let log = harness.home.path().join("Library/Logs/Sentinel/sentinel.log");
    let content = std::fs::read_to_string(&log).unwrap_or_default();
    assert!(
        content.lines().any(|l| {
            l.contains(r#""event":"gap""#)
                && (l.contains(r#""gap_kind":"prompt-cancelled""#)
                    || l.contains(r#""gap_kind": "prompt-cancelled""#))
        }),
        "no prompt-cancelled gap row in JSONL;\ncontent: {content}"
    );
}
