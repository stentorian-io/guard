//! M005-S05: D-48 'allow always (project)' rule takes effect for subsequent
//! connections IN THE SAME WRAPPED CHILD without re-prompting.
//!
//! The 7-second sleep between the two dns.lookup calls intentionally exceeds
//! the POL-03 5-second dedup window; the second lookup is allowed because
//! the daemon-appended .sentinel.toml rule is now in the active snapshot,
//! not because dedup suppressed it.

use std::io::{BufRead, BufReader, Write as _};
use std::time::{Duration, Instant};

use portable_pty::PtySize;

const DENY_HOST: &str = "discord.com";
const DENY_PORT: &str = "443";

#[cfg(target_os = "macos")]
#[test]
#[ignore = "requires PTY + non-hardened node + macOS daemon + 7s sleep — opt-in via --ignored"]
fn project_scope_rule_applies_to_second_connection_no_prompt() {
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

    // Fresh project tempdir (no .sentinel.toml). The wrapped child's cwd
    // must be inside this dir so the daemon's closest-.sentinel.toml
    // walk-up creates it here on prompt-allow-project.
    let project = tempfile::tempdir().expect("project tempdir");

    let pty_system = portable_pty::native_pty_system();
    let pair = pty_system
        .openpty(PtySize { rows: 24, cols: 80, pixel_width: 0, pixel_height: 0 })
        .expect("openpty");

    // Inline script: first lookup triggers the prompt; after the user
    // approves with "allow-always-project", sleep 7s (past the dedup
    // window), then do a second lookup to the same host. The second
    // lookup should be auto-allowed by the new .sentinel.toml rule.
    let inline = format!(
        "const dns = require('dns'); \
         dns.lookup('{DENY_HOST}', (err, addr) => {{ \
           console.log('FIRST', err ? err.code : addr); \
           setTimeout(() => {{ \
             dns.lookup('{DENY_HOST}', (err2, addr2) => {{ \
               console.log('SECOND', err2 ? err2.code : addr2); \
               process.exit(0); \
             }}); \
           }}, 7000); \
         }}); \
         setTimeout(() => process.exit(3), 30000);"
    );

    let mut cmd = portable_pty::CommandBuilder::new(&cli);
    cmd.cwd(project.path());
    cmd.arg(&node);
    cmd.arg("-e");
    cmd.arg(&inline);
    cmd.env("HOME", harness.home.path().to_str().unwrap());
    cmd.env("PATH", std::env::var("PATH").unwrap_or_default().as_str());
    cmd.env("SENTINEL_HOOK_DYLIB", dylib.to_str().unwrap());
    cmd.env("SENTINEL_STATE_DIR", harness.state_dir.to_str().unwrap());

    let mut child = pair.slave.spawn_command(cmd).expect("spawn sentinel run");
    let reader = pair.master.try_clone_reader().expect("clone reader");
    let mut writer = pair.master.take_writer().expect("take writer");
    drop(pair.slave);

    // Wait for first prompt.
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
        "first prompt never appeared; output: {full}"
    );

    // Send "3" (allow-always-project).
    writer.write_all(b"3\n").expect("write 3");

    // Drain PTY output for the duration of the wrapped command (the 7-second
    // sleep + second lookup). Use a 20s overall budget.
    let drain_deadline = Instant::now() + Duration::from_secs(20);
    while Instant::now() < drain_deadline {
        buf.clear();
        match br.read_line(&mut buf) {
            Ok(0) => break,
            Ok(_) => full.push_str(&buf),
            Err(_) => break,
        }
        if full.matches("Choose: [1]").count() >= 2 {
            break;
        }
    }
    let _ = child.wait();
    drop(writer);

    // Assert: exactly one prompt across the whole transcript.
    let prompt_count = full.matches("Choose: [1]").count();
    assert_eq!(
        prompt_count, 1,
        "expected exactly 1 prompt (project-rule should auto-allow second lookup); \
         got {prompt_count}.\nFull transcript:\n{full}"
    );

    // Assert: .sentinel.toml was created in the project dir with a [[rules]] entry.
    let policy = project.path().join(".sentinel.toml");
    assert!(
        policy.exists(),
        ".sentinel.toml not created in cwd: {}",
        policy.display()
    );
    let policy_content = std::fs::read_to_string(&policy).expect("read .sentinel.toml");
    assert!(
        policy_content.contains("[[rules]]"),
        ".sentinel.toml missing [[rules]] entry: {policy_content}"
    );

    // Assert: sentinel.log has a prompt_allow_project row (sanity).
    let log = harness
        .home
        .path()
        .join("Library/Logs/Sentinel/sentinel.log");
    let log_content = std::fs::read_to_string(&log).unwrap_or_default();
    assert!(
        log_content.lines().any(|l| {
            l.contains(r#""source_kind":"prompt_allow_project""#)
                || l.contains(r#""source_kind": "prompt_allow_project""#)
        }),
        "no prompt_allow_project row in sentinel.log: {log_content}"
    );
}
