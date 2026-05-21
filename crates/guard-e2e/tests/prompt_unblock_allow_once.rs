//! M005-S05: AllowOnce verdict via PTY prompt.
//!
//! Test: stt-guard wrap wraps node against a non-allowlisted hostname. The hook's
//! guard_getaddrinfo sends Resolve IPC to the daemon. Because the run is
//! TTY-attached, the daemon parks the Resolve and sends a PromptRequest to the
//! CLI. The test sends "1\n" (AllowOnce) into the PTY. The daemon unparks,
//! resolves DNS, returns addresses to the hook. The JSONL log records a
//! source_kind=prompt_allow_once row.
//!
//! Marked #[ignore]: requires PTY (portable-pty) + non-hardened node + macOS
//! daemon. Opt-in via:
//!   cargo test -p guard-e2e -- --ignored allow_once_unblocks

use std::io::{BufRead, BufReader, Write as _};
use std::time::{Duration, Instant};

use portable_pty::PtySize;

const DENY_HOST: &str = "discord.com";
const DENY_PORT: &str = "443";

#[cfg(target_os = "macos")]
#[test]
#[ignore = "requires PTY + non-hardened node + macOS daemon — opt-in via --ignored"]
fn allow_once_unblocks_connection_in_live_run() {
    let harness = guard_e2e::DaemonHarness::start().expect("start daemon harness");
    let cli = guard_e2e::resolve_cli();
    let dylib = guard_e2e::resolve_dylib();
    let node = match guard_e2e::resolve_node() {
        Ok(p) => p,
        Err(why) => {
            eprintln!("SKIP: {why}");
            return;
        }
    };
    let script = guard_e2e::cargo_workspace_root().join("crates/guard-e2e/harness/prompt_probe.js");

    let pty_system = portable_pty::native_pty_system();
    let pair = pty_system
        .openpty(PtySize {
            rows: 24,
            cols: 80,
            pixel_width: 0,
            pixel_height: 0,
        })
        .expect("openpty");

    let mut cmd = portable_pty::CommandBuilder::new(&cli);
    cmd.arg("wrap");
    cmd.arg(&node);
    cmd.arg(&script);
    cmd.env("HOME", harness.home.path().to_str().unwrap());
    cmd.env("PATH", std::env::var("PATH").unwrap_or_default().as_str());
    cmd.env("STT_GUARD_HOOK_DYLIB", dylib.to_str().unwrap());
    cmd.env("STT_GUARD_STATE_DIR", harness.state_dir.to_str().unwrap());
    cmd.env("PROBE_HOST", DENY_HOST);
    cmd.env("PROBE_PORT", DENY_PORT);
    cmd.env("PROBE_CONNECT_AFTER", "0");

    let mut child = pair.slave.spawn_command(cmd).expect("spawn stt-guard wrap");
    let reader = pair.master.try_clone_reader().expect("clone reader");
    let mut writer = pair.master.take_writer().expect("take writer");
    drop(pair.slave);

    let mut br = BufReader::new(reader);
    let mut buf = String::new();
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        if Instant::now() > deadline {
            panic!("prompt never appeared in PTY output within 15s; buf so far:\n{buf}");
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

    writer.write_all(b"1\n").expect("write choice 1");
    drop(writer);

    let _ = child.wait();
    std::thread::sleep(Duration::from_millis(500));

    // Assert: JSONL log has a prompt_allow_once row.
    let log = harness
        .home
        .path()
        .join("Library/Logs/Stentorian Guard/stt-guard.log");
    let content = std::fs::read_to_string(&log).unwrap_or_default();
    assert!(
        content.lines().any(|l| {
            l.contains(r#""source_kind":"prompt_allow_once""#)
                || l.contains(r#""source_kind": "prompt_allow_once""#)
        }),
        "no prompt_allow_once row found in JSONL;\ncontent: {content}"
    );
}
