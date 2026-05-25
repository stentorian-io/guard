//! Wrapped command exit code is non-zero when the user picks "deny" at the
//! prompt.
//!
//! Uses node + prompt_probe.js (non-hardened) so DYLD injection works.
//! This complements prompt_unblock_deny.rs (which only asserts the JSONL
//! source_kind=prompt_deny row).

#[cfg(target_os = "macos")]
use std::io::{BufRead, BufReader, Write as _};
#[cfg(target_os = "macos")]
use std::time::{Duration, Instant};

#[cfg(target_os = "macos")]
use portable_pty::PtySize;

#[cfg(target_os = "macos")]
const DENY_HOST: &str = "discord.com";
#[cfg(target_os = "macos")]
const DENY_PORT: &str = "443";

#[cfg(target_os = "macos")]
#[test]
#[ignore = "requires PTY + non-hardened node + macOS daemon — opt-in via --ignored"]
fn deny_choice_results_in_nonzero_exit_code() {
    let harness = guard_e2e::DaemonHarness::start().expect("start daemon");
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

    // Wait for prompt.
    let mut br = BufReader::new(reader);
    let mut full = String::new();
    let deadline = Instant::now() + Duration::from_secs(15);
    let mut buf = String::new();
    while Instant::now() < deadline {
        buf.clear();
        match br.read_line(&mut buf) {
            Ok(0) | Err(_) => break,
            Ok(_) => {}
        }
        full.push_str(&buf);
        if full.contains("Choose: [1]") {
            break;
        }
    }
    assert!(full.contains("Choose: [1]"), "no prompt: {full}");

    // Send "3" (deny).
    writer.write_all(b"3\n").expect("write 3");
    drop(writer);

    // Wait for the wrapped child to exit and capture status.
    let exit_status = child.wait().expect("wait for stt-guard wrap");
    // portable_pty::ExitStatus has a `success()` method.
    assert!(
        !exit_status.success(),
        "expected wrapped command to exit non-zero on prompt deny, got success"
    );
    assert_ne!(
        exit_status.exit_code(),
        0,
        "expected exit_code != 0, got 0; transcript: {full}"
    );
}
