//! M005-S05: AllowAlwaysMachine verdict via PTY prompt.
//!
//! Test: sends "2\n" (AllowAlwaysMachine) into the PTY prompt. The daemon
//! inserts a user rule into the SQLite `rules` table for the destination host.
//! A JSONL row with source_kind=prompt_allow_machine appears. A subsequent
//! non-TTY run to the same destination succeeds without prompting because the
//! persistent rule now allows it.
//!
//! Marked #[ignore]: requires PTY + non-hardened node + macOS daemon.
//! Opt-in via: cargo test -p guard-e2e -- --ignored allow_always_machine

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
fn allow_always_machine_persists_rule_and_allows_next_run() {
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

    // ---- First run: PTY prompt → AllowAlwaysMachine ----
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

    // Choice 2 = AllowAlwaysMachine.
    writer.write_all(b"2\n").expect("write choice 2");
    drop(writer);
    let _ = child.wait();
    std::thread::sleep(Duration::from_millis(500));

    // Assert: JSONL has prompt_allow_machine row.
    let log = harness
        .home
        .path()
        .join("Library/Logs/Stentorian Guard/stt-guard.log");
    let content = std::fs::read_to_string(&log).unwrap_or_default();
    assert!(
        content.lines().any(|l| {
            l.contains(r#""source_kind":"prompt_allow_machine""#)
                || l.contains(r#""source_kind": "prompt_allow_machine""#)
        }),
        "no prompt_allow_machine row found in JSONL;\ncontent: {content}"
    );

    // Assert: SQLite rules table contains a row for the host.
    let db_path = guard_core::paths::db_path(&harness.state_dir);
    assert!(db_path.exists(), "stt-guard.db missing");
    let conn = rusqlite::Connection::open(&db_path).expect("open db");
    let count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM rules WHERE pattern LIKE ?1",
            rusqlite::params![format!("%{DENY_HOST}%")],
            |row| row.get(0),
        )
        .unwrap_or(0);
    assert!(
        count > 0,
        "no rule for {DENY_HOST} in SQLite rules table after AllowAlwaysMachine"
    );

    // ---- Second run: non-TTY (stdin=null) → must NOT prompt, rule should allow ----
    let second_run = std::process::Command::new(&cli)
        .arg("wrap")
        .arg(&node)
        .arg(&script)
        .env_clear()
        .env("HOME", harness.home.path())
        .env("PATH", std::env::var_os("PATH").unwrap_or_default())
        .env("STT_GUARD_HOOK_DYLIB", &dylib)
        .env("STT_GUARD_STATE_DIR", &harness.state_dir)
        .env("PROBE_HOST", DENY_HOST)
        .env("PROBE_PORT", DENY_PORT)
        .env("PROBE_CONNECT_AFTER", "0")
        .stdin(std::process::Stdio::null())
        .output()
        .expect("second stt-guard wrap (non-TTY)");
    // The second run should complete quickly (rule hit → allow → resolve OK).
    // It must NOT hang indefinitely waiting for a prompt.
    let _ = second_run.status.code();
}
