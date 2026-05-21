//! TREE-06 e2e: a tracked process that calls posix_spawn with env_clear()
//! triggers EnvNotPropagatedGap; the daemon records it.
//!
//! HARD assertion (env_clear_posix_spawn_emits_gap_log_line):
//!   - Runs env_clear_posix_spawn under `stt-guard wrap`.
//!   - DaemonHarness::drain_stderr() captures the daemon child's stderr.
//!   - Assert it contains BOTH `TREE-06` AND `env-not-propagated`
//!     (case-insensitive) — both literals are emitted by
//!     handle_env_not_propagated_frame's single tracing::warn site.
//!
//! SOFT smoke (env_clear_posix_spawn_records_tree_06_gap):
//!   - Just asserts the wrapped command exits 0 (best-effort discipline:
//!     did NOT fail-closed) and the dispatch path didn't crash. Kept as a
//!     diagnostic sibling for when the HARD test fails.

use guard_e2e::{DaemonHarness, cargo_target_dir, resolve_cli, resolve_dylib};
use std::process::Command;
use std::time::Duration;

fn lc(s: &str) -> String {
    s.to_ascii_lowercase()
}

fn run_under_guard(harness: &DaemonHarness) -> std::process::Output {
    let cli = resolve_cli();
    let dylib = resolve_dylib();
    let harness_bin = cargo_target_dir().join("env_clear_posix_spawn");
    assert!(
        harness_bin.exists(),
        "harness binary missing at {} — run `cargo build --workspace` first",
        harness_bin.display()
    );

    let mut cmd = Command::new(&cli);
    cmd.arg("wrap");
    cmd.arg(&harness_bin)
        .env_clear()
        .env("HOME", harness.home.path())
        .env("PATH", std::env::var_os("PATH").unwrap_or_default())
        .env("STT_GUARD_HOOK_DYLIB", &dylib)
        .env("STT_GUARD_STATE_DIR", &harness.state_dir);

    cmd.stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .output()
        .expect("spawn stt-guard wrap")
}

/// Soft structural smoke — the wrapped command exits 0 (best-effort discipline).
/// Kept as a diagnostic sibling for the HARD test below.
#[cfg_attr(not(target_os = "macos"), ignore)]
#[test]
fn env_clear_posix_spawn_records_tree_06_gap() {
    let harness = DaemonHarness::start().expect("start daemon");
    let output = run_under_guard(&harness);
    assert!(
        output.status.success(),
        "wrapped env_clear_posix_spawn exit non-0: status={:?}\nstdout: {}\nstderr: {}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    drop(harness);
}

/// HARD assertion — empirical confirmation that the gap was recorded.
/// Uses DaemonHarness::drain_stderr (added in this Task) to capture the
/// daemon's tracing::warn line.
#[cfg_attr(not(target_os = "macos"), ignore)]
#[test]
fn env_clear_posix_spawn_emits_gap_log_line() {
    let mut harness = DaemonHarness::start().expect("start daemon");
    let output = run_under_guard(&harness);
    assert!(
        output.status.success(),
        "wrapped env_clear_posix_spawn exit non-0: status={:?}\nstdout: {}\nstderr: {}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    // The daemon writes the gap log synchronously from
    // handle_env_not_propagated_frame; allow up to 500ms for the
    // tracing layer to flush to the captured stderr pipe.
    std::thread::sleep(Duration::from_millis(500));

    let stderr = harness.drain_stderr();
    let stderr_lc = lc(&stderr);
    assert!(
        stderr_lc.contains("tree-06"),
        "daemon stderr missing `TREE-06` marker.\nstderr:\n{}",
        stderr,
    );
    assert!(
        stderr_lc.contains("env-not-propagated"),
        "daemon stderr missing `env-not-propagated` marker.\nstderr:\n{}",
        stderr,
    );
    drop(harness);
}
