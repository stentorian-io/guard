//! crates/guard-e2e/tests/status_review_non_tty.rs
//!
//! v0.7 — `status review` is interactive only.
//! Non-TTY callers must exit 64 with the "developer machine" hint emitted
//! directly by `status::review::run` (eprintln + return Ok(64) BEFORE any
//! daemon IPC), so the test does not require a live daemon.

#[cfg(target_os = "macos")]
use std::process::{Command, Stdio};

#[cfg(target_os = "macos")]
use guard_e2e::resolve_cli;

#[cfg(target_os = "macos")]
#[test]
fn status_review_non_tty_exit_64() {
    let cli = resolve_cli();
    let home = tempfile::tempdir().expect("tempdir");
    let state_dir = home.path().join(".stt-guard");

    let output = Command::new(&cli)
        .arg("status")
        .arg("review")
        .env_clear()
        .env("HOME", home.path())
        .env("PATH", std::env::var_os("PATH").unwrap_or_default())
        .env("STT_GUARD_STATE_DIR", &state_dir)
        .env("STT_GUARD_SKIP_LAUNCHCTL", "1")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("spawn stt-guard status review");

    assert_eq!(
        output.status.code(),
        Some(64),
        "expected exit 64 (EX_USAGE); got {:?}; stderr={}",
        output.status,
        String::from_utf8_lossy(&output.stderr),
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("interactive terminal") || stderr.contains("developer machine"),
        "expected non-TTY review error in stderr; got: {stderr:?}",
    );
}
