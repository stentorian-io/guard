//! M005-S05: AllowAlwaysProject verdict via PTY prompt.
//!
//! Test: sends "3\n" (AllowAlwaysProject) into the PTY prompt. The daemon
//! appends a rule to .sentinel.toml (in cwd or state_dir fallback) and inserts
//! a trusted_policy_files entry in SQLite. A JSONL row with
//! source_kind=prompt_allow_project appears.
//!
//! Marked #[ignore]: requires PTY + non-hardened node + macOS daemon.
//! Opt-in via: cargo test -p sentinel-e2e -- --ignored allow_always_project

use std::io::{BufRead, BufReader, Write as _};
use std::time::{Duration, Instant};

use portable_pty::PtySize;

const DENY_HOST: &str = "discord.com";
const DENY_PORT: &str = "443";

#[cfg(target_os = "macos")]
#[test]
#[ignore = "requires PTY + non-hardened node + macOS daemon — opt-in via --ignored"]
fn allow_always_project_appends_toml_and_trusts_policy() {
    let harness = sentinel_e2e::DaemonHarness::start().expect("start daemon harness");
    let cli = sentinel_e2e::resolve_cli();
    let dylib = sentinel_e2e::resolve_dylib();
    let node = match sentinel_e2e::resolve_node() {
        Ok(p) => p,
        Err(why) => {
            eprintln!("SKIP: {why}");
            return;
        }
    };
    let script = sentinel_e2e::cargo_workspace_root()
        .join("crates/sentinel-e2e/harness/prompt_probe.js");

    let pty_system = portable_pty::native_pty_system();
    let pair = pty_system
        .openpty(PtySize { rows: 24, cols: 80, pixel_width: 0, pixel_height: 0 })
        .expect("openpty");

    let mut cmd = portable_pty::CommandBuilder::new(&cli);
    cmd.arg(&node);
    cmd.arg(&script);
    cmd.env("HOME", harness.home.path().to_str().unwrap());
    cmd.env("PATH", std::env::var("PATH").unwrap_or_default().as_str());
    cmd.env("SENTINEL_HOOK_DYLIB", dylib.to_str().unwrap());
    cmd.env("SENTINEL_STATE_DIR", harness.state_dir.to_str().unwrap());
    cmd.env("PROBE_HOST", DENY_HOST);
    cmd.env("PROBE_PORT", DENY_PORT);
    cmd.env("PROBE_CONNECT_AFTER", "0");

    let mut child = pair.slave.spawn_command(cmd).expect("spawn");
    let reader = pair.master.try_clone_reader().expect("reader");
    let mut writer = pair.master.take_writer().expect("writer");
    drop(pair.slave);

    let mut br = BufReader::new(reader);
    let mut buf = String::new();
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        if Instant::now() > deadline {
            panic!("prompt never appeared within 15s; buf:\n{buf}");
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

    // Choice 3 = AllowAlwaysProject.
    writer.write_all(b"3\n").expect("write choice 3");
    drop(writer);
    let _ = child.wait();
    std::thread::sleep(Duration::from_millis(500));

    // Assert: JSONL has prompt_allow_project row.
    let log = harness.home.path().join("Library/Logs/Sentinel/sentinel.log");
    let content = std::fs::read_to_string(&log).unwrap_or_default();
    assert!(
        content.lines().any(|l| {
            l.contains(r#""source_kind":"prompt_allow_project""#)
                || l.contains(r#""source_kind": "prompt_allow_project""#)
        }),
        "no prompt_allow_project row in JSONL;\ncontent: {content}"
    );

    // Assert: trusted_policy_files entry in SQLite.
    let db_path = harness.state_dir.join("sentinel.db");
    let conn = rusqlite::Connection::open(&db_path).expect("open db");
    let trusted_count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM trusted_policy_files",
            [],
            |row| row.get(0),
        )
        .unwrap_or(0);
    assert!(
        trusted_count > 0,
        "no trusted_policy_files entry after AllowAlwaysProject"
    );
}
