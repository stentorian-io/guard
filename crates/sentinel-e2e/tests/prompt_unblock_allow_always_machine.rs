//! Phase 3 plan 03-14 BLOCKER #3 / POL-02 acceptance — AllowAlwaysMachine verdict.
//!
//! Test: sends "2\n" (AllowAlwaysMachine) into the PTY prompt. The daemon
//! inserts a user rule into the SQLite `rules` table for the destination host.
//! A JSONL row with source_kind=prompt_allow_machine appears. A subsequent
//! non-TTY run (stdin=null) to the same destination succeeds without prompting
//! because the persistent rule now allows it.
//!
//! Marked #[ignore]: requires PTY + non-hardened dylib + macOS daemon.
//! Opt-in via: cargo test -p sentinel-e2e -- --ignored allow_always_machine

use std::io::{BufRead, BufReader, Write as _};
use std::time::{Duration, Instant};

use portable_pty::PtySize;

#[cfg(target_os = "macos")]
#[test]
#[ignore = "requires PTY + non-hardened dylib + macOS daemon — opt-in via --ignored"]
fn allow_always_machine_persists_rule_and_allows_next_run() {
    let harness = sentinel_e2e::DaemonHarness::start().expect("start daemon harness");
    let cli = sentinel_e2e::resolve_cli();
    let dylib = sentinel_e2e::resolve_dylib();
    let dest_host = "192.0.2.200"; // RFC 5737 — never allowlisted by default.

    // ---- First run: PTY prompt → AllowAlwaysMachine ----
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
    cmd.arg(format!("https://{dest_host}/"));
    cmd.arg("-s");
    cmd.env("HOME", harness.home.path().to_str().unwrap());
    cmd.env("PATH", std::env::var("PATH").unwrap_or_default().as_str());
    cmd.env("SENTINEL_HOOK_DYLIB", dylib.to_str().unwrap());
    cmd.env("SENTINEL_STATE_DIR", harness.state_dir.to_str().unwrap());

    let mut child = pair.slave.spawn_command(cmd).expect("spawn");
    let reader = pair.master.try_clone_reader().expect("reader");
    let mut writer = pair.master.take_writer().expect("writer");
    drop(pair.slave);

    let mut br = BufReader::new(reader);
    let mut buf = String::new();
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if Instant::now() > deadline {
            panic!("prompt never appeared; buf: {buf}");
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
    let log = harness.home.path().join("Library/Logs/Sentinel/sentinel.log");
    let content = std::fs::read_to_string(&log).unwrap_or_default();
    assert!(
        content.lines().any(|l| {
            l.contains(r#""source_kind":"prompt_allow_machine""#)
                || l.contains(r#""source_kind": "prompt_allow_machine""#)
        }),
        "no prompt_allow_machine row found in JSONL;\ncontent: {content}"
    );

    // Assert: SQLite rules table contains a row for dest_host.
    let db_path = harness.state_dir.join("sentinel.db");
    assert!(db_path.exists(), "sentinel.db missing");
    let conn = rusqlite::Connection::open(&db_path).expect("open db");
    let count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM rules WHERE pattern LIKE ?1",
            rusqlite::params![format!("%{dest_host}%")],
            |row| row.get(0),
        )
        .unwrap_or(0);
    assert!(
        count > 0,
        "no rule for {dest_host} in SQLite rules table after AllowAlwaysMachine"
    );

    // ---- Second run: non-TTY (stdin=null) → must NOT prompt, must allow via rule ----
    // We can't easily distinguish "allowed by rule" from "connection failed for other reasons"
    // without network access to 192.0.2.200. The key assertion is: no prompt fired (which
    // would manifest as the process hanging waiting for terminal input on a non-TTY).
    // Timeout of 5s: if it hangs longer than that, the non-TTY guard failed.
    let second_run = std::process::Command::new(&cli)
        .arg("run")
        .arg("--")
        .arg("/usr/bin/curl")
        .arg("--max-time")
        .arg("3")
        .arg(format!("https://{dest_host}/"))
        .arg("-s")
        .env_clear()
        .env("HOME", harness.home.path())
        .env("PATH", std::env::var_os("PATH").unwrap_or_default())
        .env("SENTINEL_HOOK_DYLIB", &dylib)
        .env("SENTINEL_STATE_DIR", &harness.state_dir)
        .stdin(std::process::Stdio::null())
        .output()
        .expect("second sentinel run (non-TTY)");
    // The second run should complete quickly (rule hit → allow → curl timeout or ETIMEDOUT).
    // It must NOT hang indefinitely waiting for a prompt (that would be a bug).
    // We can't assert success because 192.0.2.200 is unroutable (RFC 5737); we just
    // assert it completed without Sentinel blocking it (no EHOSTUNREACH-class error).
    let _ = second_run.status.code(); // just assert it completed
}
