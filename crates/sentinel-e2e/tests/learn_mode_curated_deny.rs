//! Learn-mode hard-deny: curated BuiltinDeny still blocks under --learn.
//!
//! `*.workers.dev` is in the curated YAML deny list with tier=BuiltinDeny.
//! Even with `--learn`, ConfirmedDeny and BuiltinDeny are non-overridable
//! hard blocks — the learn-mode passthrough only applies to DefaultDeny,
//! UserDeny, and SuspectDeny.
//!
//! Requires PTY because `--learn` gates on stdin_is_tty().
//! Opt-in via: cargo test -p sentinel-e2e -- --ignored learn_mode_still_blocks

use std::time::Duration;

use portable_pty::PtySize;

const DENY_HOST: &str = "sentinel-test.workers.dev";
const DENY_PORT: &str = "443";

#[cfg(target_os = "macos")]
#[test]
#[ignore = "requires PTY + non-hardened node + macOS daemon — opt-in via --ignored"]
fn learn_mode_still_blocks_curated_builtin_deny() {
    let cli = sentinel_e2e::resolve_cli();
    let dylib = sentinel_e2e::resolve_dylib();
    let node = match sentinel_e2e::resolve_node() {
        Ok(p) => p,
        Err(why) => {
            eprintln!("SKIP: {why}");
            return;
        }
    };
    let harness = sentinel_e2e::DaemonHarness::start().expect("start daemon");
    let script = sentinel_e2e::cargo_workspace_root()
        .join("crates/sentinel-e2e/harness/connect_workers_dev.js");
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
    cmd.env(
        "PATH",
        std::env::var("PATH").unwrap_or_default().as_str(),
    );
    cmd.env("SENTINEL_HOOK_DYLIB", dylib.to_str().unwrap());
    cmd.env("SENTINEL_STATE_DIR", harness.state_dir.to_str().unwrap());
    cmd.env("SENTINEL_TEST_DENY_HOST", DENY_HOST);
    cmd.env("SENTINEL_TEST_DENY_PORT", DENY_PORT);

    let mut child = pair.slave.spawn_command(cmd).expect("spawn sentinel wrap --learn");
    let reader = pair.master.try_clone_reader().expect("clone reader");
    drop(pair.slave);

    // Collect all PTY output until the process exits or timeout.
    let buf = match sentinel_e2e::read_pty_until(
        reader,
        "CONNECT-FAILED",
        Duration::from_secs(15),
    ) {
        Ok(b) => b,
        Err(e) => {
            // Even if the needle wasn't found, the buffer may have useful output.
            // The process may have exited with the marker on the last line.
            eprintln!("PTY read note: {e}");
            String::new()
        }
    };

    let status = child.wait().expect("wait for sentinel");

    // BuiltinDeny must still block — the wrapped node exits non-zero.
    assert!(
        !status.success(),
        "learn-mode must NOT bypass BuiltinDeny (workers.dev should be blocked)\n\
         PTY output:\n{buf}"
    );

    assert!(
        buf.contains("CONNECT-FAILED"),
        "expected CONNECT-FAILED in PTY output (proves deny path fired); got:\n{buf}"
    );

    // ECONNREFUSED would mean Sentinel let the connect through.
    assert!(
        !buf.contains("ECONNREFUSED"),
        "ECONNREFUSED means Sentinel let workers.dev through — BuiltinDeny \
         bypass regression in learn mode. Got:\n{buf}"
    );

    // The learn-review prompt should NOT appear (no hosts were staged —
    // BuiltinDeny blocks without staging).
    assert!(
        !buf.contains("[a]llow"),
        "learn review prompt appeared after BuiltinDeny — hosts should not be \
         staged for review when hard-denied. Got:\n{buf}"
    );
}
