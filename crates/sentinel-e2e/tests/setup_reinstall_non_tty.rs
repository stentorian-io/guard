//! crates/sentinel-e2e/tests/setup_reinstall_non_tty.rs
//!
//! Phase 07 plan 05 — CLI-13 + CLI-20 + D-17/D-18: `setup --reinstall`
//! without -y must refuse non-TTY callers (the destruction prompt requires
//! TTY so a piped `yes` can't agree to wipe rules+logs+trust).
//!
//! Same exit-code shape as setup_remove_non_tty.rs: 64 or 70 (CliError::Other
//! from tty::confirm propagates to exit 70 via main.rs).

use std::process::{Command, Stdio};

use sentinel_e2e::resolve_cli;

#[cfg(target_os = "macos")]
#[test]
fn setup_reinstall_non_tty_refuses_without_yes() {
    let cli = resolve_cli();
    let home = tempfile::tempdir().expect("tempdir");
    let state_dir = home.path().join(".sentinel");

    let output = Command::new(&cli)
        .arg("setup").arg("--reinstall")
        .env_clear()
        .env("HOME", home.path())
        .env("PATH", std::env::var_os("PATH").unwrap_or_default())
        .env("SENTINEL_STATE_DIR", &state_dir)
        .env("SENTINEL_SKIP_LAUNCHCTL", "1")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("spawn sentinel setup --reinstall");

    let exit = output.status.code();
    assert!(
        matches!(exit, Some(64) | Some(70)),
        "expected exit 64 or 70 (TTY-required); got {exit:?}; stderr={}",
        String::from_utf8_lossy(&output.stderr),
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("TTY required") || stderr.contains("interactive terminal"),
        "expected TTY-required error in stderr; got: {stderr:?}",
    );
}
