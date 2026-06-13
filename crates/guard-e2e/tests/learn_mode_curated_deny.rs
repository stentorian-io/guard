#![cfg(target_os = "macos")]

//! Learn-mode hard-deny: curated `BuiltinDeny` still blocks under `--learn`.
//!
//! `*.workers.dev` is in the curated YAML deny list with tier `BuiltinDeny`.
//! Even with `--learn`, `ConfirmedDeny` and `BuiltinDeny` are non-overridable
//! hard blocks -- the learn-mode passthrough only applies to `DefaultDeny`,
//! `UserDeny`, and `SuspectDeny`.
//!
//! Uses `connect_workers_dev.js` which calls `net.connect()` -- the hook
//! intercepts at the `connect()` syscall level using the in-process snapshot.
//! No daemon Resolve IPC is involved (the host is denied before DNS).
//!
//! Differential companion: `learn_mode_default_deny_passthrough.rs` verifies
//! that `DefaultDeny` hosts ARE allowed through in learn mode.
//!
//! Requires PTY because `--learn` gates on `stdin_is_tty()`.
//! Opt-in via: `cargo test -p guard-e2e -- --ignored learn_mode_still_blocks`

#[cfg(target_os = "macos")]
use std::time::Duration;

#[cfg(target_os = "macos")]
use portable_pty::PtySize;

#[cfg(target_os = "macos")]
const DENY_HOST: &str = "guard-test.workers.dev";
#[cfg(target_os = "macos")]
const DENY_PORT: &str = "443";

#[cfg(target_os = "macos")]
#[test]
#[ignore = "requires PTY + non-hardened node + macOS daemon -- opt-in via --ignored"]
fn learn_mode_still_blocks_curated_builtin_deny() {
    let cli = guard_e2e::resolve_cli();
    let dylib = guard_e2e::resolve_dylib();
    let node = match guard_e2e::resolve_node() {
        Ok(p) => p,
        Err(why) => {
            eprintln!("SKIP: {why}");
            return;
        }
    };
    let harness = guard_e2e::DaemonHarness::start().expect("start daemon");
    let script =
        guard_e2e::cargo_workspace_root().join("crates/guard-e2e/harness/connect_workers_dev.js");
    assert!(
        script.exists(),
        "harness script missing at {}",
        script.display()
    );

    let pty_system = portable_pty::native_pty_system();
    let pair = pty_system
        .openpty(PtySize {
            rows: 24,
            cols: 120,
            pixel_width: 0,
            pixel_height: 0,
        })
        .expect("openpty");

    let mut cmd = portable_pty::CommandBuilder::new(&cli);
    cmd.arg("wrap");
    cmd.arg("--learn");
    cmd.arg(&node);
    cmd.arg(&script);
    cmd.env("HOME", harness.home.path().to_str().unwrap());
    cmd.env("PATH", std::env::var("PATH").unwrap_or_default().as_str());
    cmd.env("STT_GUARD_HOOK_DYLIB", dylib.to_str().unwrap());
    cmd.env("STT_GUARD_STATE_DIR", harness.state_dir.to_str().unwrap());
    cmd.env("STT_GUARD_TEST_DENY_HOST", DENY_HOST);
    cmd.env("STT_GUARD_TEST_DENY_PORT", DENY_PORT);

    let mut child = pair
        .slave
        .spawn_command(cmd)
        .expect("spawn stt-guard wrap --learn");
    let reader = pair.master.try_clone_reader().expect("clone reader");
    drop(pair.slave);

    // Wait for the process to complete. The connect_workers_dev.js script
    // prints "CONNECT-FAILED" when the hook denies at connect(). We use
    // read_pty_until to capture output up to that marker or timeout.
    let buf = guard_e2e::read_pty_until(reader, "CONNECT-FAILED", Duration::from_secs(15))
        .unwrap_or_else(|e| {
            // If the needle was not found, the error message includes the
            // buffer contents. Extract it for assertion diagnostics.
            panic!(
                "expected CONNECT-FAILED in PTY output (BuiltinDeny should fire \
                 at connect() level); read_pty_until error: {e}"
            );
        });

    let status = child.wait().expect("wait for stt-guard");

    // BuiltinDeny must still block -- the wrapped node exits non-zero.
    assert!(
        !status.success(),
        "learn-mode must NOT bypass BuiltinDeny (workers.dev should be blocked)\n\
         PTY output:\n{buf}"
    );

    assert!(
        buf.contains("CONNECT-FAILED"),
        "expected CONNECT-FAILED in PTY output (proves deny path fired); got:\n{buf}"
    );

    // ECONNREFUSED would mean Stentorian Guard let the connect through to the network.
    assert!(
        !buf.contains("ECONNREFUSED"),
        "ECONNREFUSED means Stentorian Guard let workers.dev through -- BuiltinDeny \
         bypass regression in learn mode. Got:\n{buf}"
    );

    // The learn-review prompt should NOT appear -- BuiltinDeny blocks without
    // staging hosts for end-of-run review.
    assert!(
        !buf.contains("[a]llow"),
        "learn review prompt appeared after BuiltinDeny -- hosts should not be \
         staged for review when hard-denied. Got:\n{buf}"
    );
}
