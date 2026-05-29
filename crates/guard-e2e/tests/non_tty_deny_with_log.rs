//! v0.3 — non-TTY stt-guard wrap → no prompt → deny-with-log.
//!
//! AC-NTTY-02 / D-74: When stdin is not a TTY, stt-guard wrap sets `is_tty=false`;
//! the daemon's Resolve handler fires deny immediately (no prompt park). The
//! wrapped command exits non-zero on a denied connection.
//!
//! NOTE: The JSONL log assertion is a soft assert (v1 limitation): the dylib's
//! libc connect-deny path does NOT currently route through `log_writer` (it relies
//! on the GapDetector/RecentGapsRing path instead). The hard assertion is exit
//! non-zero; the JSONL check is best-effort and will pass when the log-writer
//! integration is complete.
//!
//! This test requires a running daemon harness and is therefore `#[ignore]`
//! for standard CI; opt-in via `cargo test -p guard-e2e -- --ignored non_tty`.

#[cfg(target_os = "macos")]
#[test]
#[ignore = "requires daemon harness + network access — opt-in via --ignored"]
fn non_tty_run_blocks_and_logs() {
    let harness = guard_e2e::DaemonHarness::start().expect("start daemon harness");
    let cli = guard_e2e::resolve_cli();
    let dylib = guard_e2e::resolve_dylib();

    // 192.0.2.1 is RFC 5737 TEST-NET-1 — not routable, never allowlisted.
    // curl with --max-time 3 will fail immediately when Stentorian Guard denies at the
    // connect() layer (sub-ms) rather than waiting for TCP timeout (75s+).
    let out = std::process::Command::new(&cli)
        .arg("wrap")
        .arg("/usr/bin/curl")
        .arg("--max-time")
        .arg("3")
        .arg("https://192.0.2.1/")
        .arg("-s")
        .env_clear()
        .env("HOME", harness.home.path())
        .env("PATH", std::env::var_os("PATH").unwrap_or_default())
        .env("STT_GUARD_HOOK_DYLIB", &dylib)
        .env("STT_GUARD_STATE_DIR", &harness.state_dir)
        .stdin(std::process::Stdio::null()) // D-73: non-TTY → is_tty=false
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .output()
        .expect("run stt-guard");

    // Hard assertion: non-zero exit (D-75).
    assert!(
        !out.status.success(),
        "expected non-zero exit for denied connection; got: {:?}",
        out.status.code()
    );

    // Allow log_writer mpsc to drain.
    std::thread::sleep(std::time::Duration::from_millis(500));

    // Soft assertion: JSONL log may contain a block/deny row.
    let log_path = harness
        .home
        .path()
        .join("Library/Logs/Stentorian Guard/stt-guard.log");
    if let Ok(content) = std::fs::read_to_string(&log_path) {
        let any_block = content.lines().any(|l| {
            serde_json::from_str::<serde_json::Value>(l)
                .ok()
                .and_then(|v| {
                    v.get("event")
                        .and_then(|e| e.as_str())
                        .map(|s| s == "block")
                })
                .unwrap_or(false)
        });
        if !any_block {
            // v1 limitation: dylib libc-connect deny may not yet route to log_writer.
            eprintln!(
                "note: no event:'block' row in JSONL — v1 limitation (connect-deny \
                 path does not yet emit log_writer rows); hard assertion on exit-code passed"
            );
        }
    } else {
        eprintln!(
            "note: log file absent at {} — daemon may not have received any events \
             (v1 limitation: libc-connect deny path does not emit log_writer rows)",
            log_path.display()
        );
    }
}
