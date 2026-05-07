//! Phase 3 plan 03-18 (gap closure for UAT item #3) — POL-03 5-second
//! batching/dedup window.
//!
//! Spawns two concurrent connects to the same (host, port) inside one
//! wrapped child via `curl ... & curl ... & wait`. The dedup keyed on
//! (run_uuid, host, port) MUST collapse the two attempts into a single
//! prompt. The test writes "1\n" once and asserts the PTY received
//! exactly one "Choose: [1]" line.

use std::io::{BufRead, BufReader, Write as _};
use std::time::{Duration, Instant};

use portable_pty::PtySize;

#[cfg(target_os = "macos")]
#[test]
#[ignore = "requires PTY + non-hardened dylib + macOS daemon — opt-in via --ignored"]
fn second_attempt_within_5s_does_not_reprompt() {
    let harness = sentinel_e2e::DaemonHarness::start().expect("start daemon");
    let cli = sentinel_e2e::resolve_cli();
    let dylib = sentinel_e2e::resolve_dylib();

    let pty_system = portable_pty::native_pty_system();
    let pair = pty_system
        .openpty(PtySize { rows: 24, cols: 80, pixel_width: 0, pixel_height: 0 })
        .expect("openpty");

    let mut cmd = portable_pty::CommandBuilder::new(&cli);
    cmd.arg("run");
    cmd.arg("--");
    cmd.arg("/bin/sh");
    cmd.arg("-c");
    cmd.arg(
        "/usr/bin/curl --max-time 5 -s https://192.0.2.123/ & \
         /usr/bin/curl --max-time 5 -s https://192.0.2.123/ & \
         wait",
    );
    cmd.env("HOME", harness.home.path().to_str().unwrap());
    cmd.env("PATH", std::env::var("PATH").unwrap_or_default().as_str());
    cmd.env("SENTINEL_HOOK_DYLIB", dylib.to_str().unwrap());
    cmd.env("SENTINEL_STATE_DIR", harness.state_dir.to_str().unwrap());

    let mut child = pair.slave.spawn_command(cmd).expect("spawn sentinel run");
    let reader = pair.master.try_clone_reader().expect("clone reader");
    let mut writer = pair.master.take_writer().expect("take writer");
    drop(pair.slave);

    // Read PTY until we see the first prompt or timeout.
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
    assert!(
        full.contains("Choose: [1]"),
        "first prompt never appeared within 10s; output so far: {full}"
    );

    // Send "1" (allow-once). Both pending connects should be unblocked.
    writer.write_all(b"1\n").expect("write 1");

    // Drain remaining PTY output for ~3 more seconds (PTY may have
    // additional bytes after both connects complete).
    let drain_deadline = Instant::now() + Duration::from_secs(3);
    while Instant::now() < drain_deadline {
        buf.clear();
        match br.read_line(&mut buf) {
            Ok(0) => break,
            Ok(_) => full.push_str(&buf),
            Err(_) => break,
        }
    }
    let _ = child.wait();
    drop(writer);

    // Hard assertion: exactly ONE "Choose: [1]" occurrence in the entire
    // PTY transcript. If dedup is broken, two prompts fire and the count
    // would be 2.
    let prompt_count = full.matches("Choose: [1]").count();
    assert_eq!(
        prompt_count, 1,
        "POL-03 dedup violation: expected exactly 1 prompt for two \
         concurrent connects to same (host, port), got {prompt_count}.\n\
         Full PTY transcript:\n{full}"
    );
}
