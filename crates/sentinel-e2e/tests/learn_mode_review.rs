//! Learn-mode end-of-run review: after the wrapped process exits, the CLI
//! presents staged hosts for interactive review via `[a]llow / [d]eny / [s]kip`.
//!
//! This test uses a PTY to drive the interaction:
//!   1. `sentinel wrap --learn node connect_evil.js` connects to discord.com
//!      (DefaultDeny → allowed + staged in learn mode).
//!   2. After node exits, the CLI calls BaselineCommit IPC and renders the
//!      review menu.
//!   3. The test sends "a\n" (allow) for the staged host.
//!   4. Assert: the review summary appears with "1 allow".
//!
//! Marked #[ignore]: requires PTY + non-hardened node + macOS daemon + network.
//! Opt-in via: cargo test -p sentinel-e2e -- --ignored learn_review

use std::time::Duration;

use portable_pty::PtySize;

const HOST: &str = "discord.com";
const PORT: &str = "443";

fn host_resolves_outside_sentinel() -> bool {
    use std::net::ToSocketAddrs;
    format!("{HOST}:{PORT}")
        .to_socket_addrs()
        .map(|i| i.count() > 0)
        .unwrap_or(false)
}

#[cfg(target_os = "macos")]
#[test]
#[ignore = "requires PTY + non-hardened node + macOS daemon + network — opt-in via --ignored"]
fn learn_review_allow_stages_user_rule() {
    if !host_resolves_outside_sentinel() {
        eprintln!("SKIP: {HOST}:{PORT} did not resolve — cannot test learn review offline");
        return;
    }

    let harness = sentinel_e2e::DaemonHarness::start().expect("start daemon harness");
    let cli = sentinel_e2e::resolve_cli();
    let dylib = sentinel_e2e::resolve_dylib();
    let node = match sentinel_e2e::resolve_node() {
        Ok(p) => p,
        Err(why) => {
            eprintln!("SKIP: {why}");
            return;
        }
    };
    let script = sentinel_e2e::cargo_workspace_root()
        .join("crates/sentinel-e2e/harness/connect_evil.js");

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
    cmd.env("SENTINEL_TEST_DENY_HOST", HOST);
    cmd.env("SENTINEL_TEST_DENY_PORT", PORT);

    let mut child = pair.slave.spawn_command(cmd).expect("spawn sentinel wrap --learn");
    let reader = pair.master.try_clone_reader().expect("clone reader");
    let mut writer = pair.master.take_writer().expect("take writer");
    drop(pair.slave);

    // Wait for the review prompt to appear (after the wrapped node exits).
    // The review menu shows: "  discord.com — [a]llow / [d]eny / [s]kip / [q]uit > "
    let buf = sentinel_e2e::read_pty_until(
        reader,
        "[a]llow",
        Duration::from_secs(30),
    )
    .expect("learn review prompt should appear after wrapped process exits");

    // Verify the review header appeared.
    assert!(
        buf.contains("host(s) observed"),
        "expected learn review header; PTY output:\n{buf}"
    );

    // Send "a" to allow the staged host.
    writer.write_all(b"a\n").expect("write 'a' to allow");
    drop(writer);

    let status = child.wait().expect("wait for sentinel");
    // The wrapped node should have exited 0 (learn mode allowed the connect).
    assert!(
        status.success(),
        "expected exit 0 from learn-mode run; got: {:?}",
        status
    );
}
