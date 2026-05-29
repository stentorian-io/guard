//! Learn-mode TTY gate: `--learn` without a TTY exits 64 (`EX_USAGE`).
//!
//! `--learn` requires an interactive terminal because the end-of-run review
//! presents staged hosts for the developer to allow/deny. Without a TTY the
//! review is impossible, so the CLI rejects early with exit 64 and a clear
//! stderr message.
//!
//! This test does NOT require a daemon, PTY, or network access — the TTY
//! check fires before any IPC or process spawning.

#[cfg(target_os = "macos")]
use std::process::{Command, Stdio};

#[cfg(target_os = "macos")]
#[test]
fn learn_mode_without_tty_exits_64() {
    let cli = guard_e2e::resolve_cli();

    let output = Command::new(&cli)
        .arg("wrap")
        .arg("--learn")
        .arg("echo")
        .arg("hello")
        .env_remove("STT_GUARD_HOOK_DYLIB")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("spawn stt-guard wrap --learn");

    assert_eq!(
        output.status.code(),
        Some(64),
        "expected exit 64 (EX_USAGE) when --learn is used without TTY; got {:?}\n\
         stderr: {}",
        output.status.code(),
        String::from_utf8_lossy(&output.stderr),
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("interactive terminal"),
        "expected 'interactive terminal' in stderr; got: {stderr:?}",
    );
}
