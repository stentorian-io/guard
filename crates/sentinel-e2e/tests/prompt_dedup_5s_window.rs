//! M005-S05: POL-03 5-second batching/dedup window.
//!
//! Spawns two concurrent dns.lookup calls to the same (host, port) inside one
//! wrapped child. The dedup keyed on (run_uuid, host, port) MUST collapse the
//! two attempts into a single prompt. The test writes "1\n" once and asserts
//! the PTY received exactly one "Choose: [1]" line.

use std::io::{BufRead, BufReader, Write as _};
use std::time::{Duration, Instant};

use portable_pty::PtySize;

const DENY_HOST: &str = "discord.com";
const DENY_PORT: &str = "443";

#[cfg(target_os = "macos")]
#[test]
#[ignore = "requires PTY + non-hardened node + macOS daemon — opt-in via --ignored"]
fn second_attempt_within_5s_does_not_reprompt() {
    let harness = sentinel_e2e::DaemonHarness::start().expect("start daemon");
    let cli = sentinel_e2e::resolve_cli();
    let dylib = sentinel_e2e::resolve_dylib();
    let node = match sentinel_e2e::resolve_node() {
        Ok(p) => p,
        Err(why) => {
            eprintln!("SKIP: {why}");
            return;
        }
    };

    let pty_system = portable_pty::native_pty_system();
    let pair = pty_system
        .openpty(PtySize { rows: 24, cols: 80, pixel_width: 0, pixel_height: 0 })
        .expect("openpty");

    // Inline script: two concurrent dns.lookup calls for the same host.
    // Both fire getaddrinfo → Resolve IPC → daemon parks. Dedup should
    // collapse them into a single prompt.
    let inline = format!(
        "const dns = require('dns'); \
         dns.lookup('{DENY_HOST}', () => {{}}); \
         dns.lookup('{DENY_HOST}', () => {{}}); \
         setTimeout(() => process.exit(0), 10000);"
    );

    let mut cmd = portable_pty::CommandBuilder::new(&cli);
    cmd.arg("wrap");
    cmd.arg(&node);
    cmd.arg("-e");
    cmd.arg(&inline);
    cmd.env("HOME", harness.home.path().to_str().unwrap());
    cmd.env("PATH", std::env::var("PATH").unwrap_or_default().as_str());
    cmd.env("SENTINEL_HOOK_DYLIB", dylib.to_str().unwrap());
    cmd.env("SENTINEL_STATE_DIR", harness.state_dir.to_str().unwrap());

    let mut child = pair.slave.spawn_command(cmd).expect("spawn sentinel wrap");
    let reader = pair.master.try_clone_reader().expect("clone reader");
    let mut writer = pair.master.take_writer().expect("take writer");
    drop(pair.slave);

    // Read PTY until we see the first prompt or timeout.
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
    assert!(
        full.contains("Choose: [1]"),
        "first prompt never appeared within 15s; output so far: {full}"
    );

    // Send "1" (allow-once). Both pending lookups should be unblocked.
    writer.write_all(b"1\n").expect("write 1");

    // Drain remaining PTY output for ~3 more seconds.
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
    // PTY transcript. If dedup is broken, two prompts fire.
    let prompt_count = full.matches("Choose: [1]").count();
    assert_eq!(
        prompt_count, 1,
        "POL-03 dedup violation: expected exactly 1 prompt for two \
         concurrent lookups to same host, got {prompt_count}.\n\
         Full PTY transcript:\n{full}"
    );
}
