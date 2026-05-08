//! Phase 3 plan 03-18 (gap closure for UAT item #3) — D-75 wrapped command
//! exit code is non-zero when the user picks "deny" at the prompt.
//!
//! This complements prompt_unblock_deny.rs (which only asserts the JSONL
//! source_kind=prompt_deny row).

use std::io::{BufRead, BufReader, Write as _};
use std::time::{Duration, Instant};

use portable_pty::PtySize;

#[cfg(target_os = "macos")]
#[test]
#[ignore = "requires PTY + non-hardened dylib + macOS daemon — opt-in via --ignored"]
fn deny_choice_results_in_nonzero_exit_code() {
    let harness = sentinel_e2e::DaemonHarness::start().expect("start daemon");
    let cli = sentinel_e2e::resolve_cli();
    let dylib = sentinel_e2e::resolve_dylib();

    let pty_system = portable_pty::native_pty_system();
    let pair = pty_system
        .openpty(PtySize { rows: 24, cols: 80, pixel_width: 0, pixel_height: 0 })
        .expect("openpty");

    let mut cmd = portable_pty::CommandBuilder::new(&cli);
    cmd.arg("/usr/bin/curl");
    cmd.arg("--max-time");
    cmd.arg("5");
    cmd.arg("-s");
    cmd.arg("https://192.0.2.123/");
    cmd.env("HOME", harness.home.path().to_str().unwrap());
    cmd.env("PATH", std::env::var("PATH").unwrap_or_default().as_str());
    cmd.env("SENTINEL_HOOK_DYLIB", dylib.to_str().unwrap());
    cmd.env("SENTINEL_STATE_DIR", harness.state_dir.to_str().unwrap());

    let mut child = pair.slave.spawn_command(cmd).expect("spawn sentinel run");
    let reader = pair.master.try_clone_reader().expect("clone reader");
    let mut writer = pair.master.take_writer().expect("take writer");
    drop(pair.slave);

    // Wait for prompt.
    let mut br = BufReader::new(reader);
    let mut full = String::new();
    let deadline = Instant::now() + Duration::from_secs(10);
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

    // Send "4" (deny).
    writer.write_all(b"4\n").expect("write 4");
    drop(writer);

    // Wait for the wrapped child to exit and capture status.
    let exit_status = child.wait().expect("wait for sentinel run");
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
