//! v0.1 milestone audit BLOCKER #1 closure (LOG-02 + VAL-01) — dylib-side
//! pm_env capture lands AND obvious secrets never cross the IPC wire.
//!
//! Originally `#[ignore]`'d during plan 03-14 because the dylib half of the
//! pm_env capture pipeline was missing. quick-260508-et9 wired it in: the
//! exec/posix_spawn shadows now walk envp at exec time and pass the filtered
//! `Vec<(String,String)>` into `send_exec_event_sync`.
//!
//! Two assertions:
//!   1. POSITIVE: an info-level tracing line `pm_env_captured` appears in the
//!      daemon's stderr — proves the V3 ExecEvent reached the handler with a
//!      non-empty pm_env field, which only happens when the dylib's
//!      `pm_env_filter::extract_pm_env_from_envp_mut` admitted entries from
//!      our explicit envp.
//!   2. NEGATIVE: decoy denylisted secret values NEVER appear anywhere in the
//!      daemon stderr OR the JSONL stt-guard.log — defense-in-depth across two
//!      trust layers (dylib-side filter + daemon-side re-filter, both
//!      mirroring `guard_daemon::env_capture`).
//!
//! Wraps the `pm_env_posix_spawn` harness (a small Rust bin under
//! crates/guard-e2e/harness/pm_env_posix_spawn). The harness calls
//! `libc::posix_spawn` directly with an explicit envp containing both benign
//! PM env vars (must be captured) and decoy secrets (must be filtered out).
//! Wrapping a Rust binary we control avoids depending on whether the system
//! `node` binary triggers any internal posix_spawn during a `node -e ""`
//! invocation.

use guard_e2e::{DaemonHarness, cargo_target_dir, resolve_cli, resolve_dylib};
use std::process::Command;
use std::time::Duration;

const TRACING_MARKER: &str = "pm_env_captured";

#[cfg_attr(not(target_os = "macos"), ignore)]
#[test]
fn cargo_registry_token_never_leaks_to_log() {
    let cli = resolve_cli();
    let dylib = resolve_dylib();
    let harness_bin = cargo_target_dir().join("pm_env_posix_spawn");
    assert!(
        harness_bin.exists(),
        "pm_env_posix_spawn harness missing at {} — run `cargo build --workspace` first",
        harness_bin.display()
    );

    let mut harness = DaemonHarness::start().expect("start daemon harness");

    let output = Command::new(&cli)
        .arg("wrap")
        .arg(&harness_bin)
        .env_clear()
        .env("HOME", harness.home.path())
        .env("PATH", std::env::var_os("PATH").unwrap_or_default())
        .env("STT_GUARD_HOOK_DYLIB", &dylib)
        .env("STT_GUARD_STATE_DIR", &harness.state_dir)
        .output()
        .expect("run stt-guard");

    // Allow the daemon's tracing layer to drain (info!() is buffered briefly).
    std::thread::sleep(Duration::from_millis(500));

    let stderr = harness.drain_stderr();
    let log_path = harness
        .home
        .path()
        .join("Library/Logs/Stentorian Guard/stt-guard.log");
    let log_content = std::fs::read_to_string(&log_path).unwrap_or_default();

    // POSITIVE assertion: capture worked end-to-end. The `pm_env_captured`
    // tracing line is emitted at info-level by ipc_server::handle_exec_event_frame
    // when the daemon-side extract_pm_env returns a non-empty Vec (which only
    // happens when the dylib sent a non-empty pm_env field on the wire).
    assert!(
        stderr.contains(TRACING_MARKER),
        "expected `{TRACING_MARKER}` in daemon stderr — pm_env capture did not reach the daemon.\n\
         wrapped harness exit: {:?}\n\
         daemon stderr:\n{stderr}\n\
         stt-guard.log content (head 2KB):\n{}",
        output.status,
        log_content.chars().take(2048).collect::<String>(),
    );

    // NEGATIVE assertions: the decoy values must NEVER appear in either the
    // daemon stderr OR the JSONL log. The dylib-side filter drops them before
    // the IPC wire, and the daemon-side filter re-drops them on receipt as
    // defense in depth.
    let combined_haystack = format!("{stderr}\n---\n{log_content}");
    assert!(
        !combined_haystack.contains("DECOY_should_not_leak_npm_token"),
        "NPM_TOKEN value leaked!\nstderr: {stderr}\nlog: {log_content}"
    );
    assert!(
        !combined_haystack.contains("DECOY_should_not_leak_cargo_token"),
        "CARGO_REGISTRY_TOKEN value leaked!\nstderr: {stderr}\nlog: {log_content}"
    );
    assert!(
        !combined_haystack.contains("DECOY_should_not_leak_npm_authToken"),
        "npm_config_authToken value leaked!\nstderr: {stderr}\nlog: {log_content}"
    );
}
