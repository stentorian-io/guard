//! Learn-mode passthrough: DefaultDeny hosts are allowed and staged.
//!
//! In normal mode `discord.com` triggers DefaultDeny (not in any allowlist).
//! In `--learn` mode the hook allows the connection through, stages the host
//! for end-of-run review, and the wrapped process connects successfully.
//!
//! Uses `connect_evil.js` with `STT_GUARD_TEST_DENY_HOST=discord.com` which
//! calls `net.connect()`. Node performs its own internal DNS resolution
//! (libuv thread-pool getaddrinfo), then calls connect() with the resolved
//! IP. The hook's getaddrinfo interpose proxies through the daemon which
//! stages the host in learn mode. The subsequent connect() is then allowed.
//!
//! After the wrapped process exits, the CLI presents the learn review prompt
//! for staged hosts. The test sends 's' (skip) and asserts exit 0.
//!
//! Differential companion: `learn_mode_curated_deny.rs` verifies that
//! BuiltinDeny still blocks in learn mode.
//!
//! Requires PTY + non-hardened node + daemon + network + working getaddrinfo
//! interpose. The getaddrinfo interpose depends on DYLD injection working for
//! the libuv thread-pool path, which is fragile on some dev machines.
//! Opt-in via: `cargo test -p guard-e2e -- --ignored learn_mode_allows`

use std::io::Write as _;
use std::time::Duration;

use portable_pty::PtySize;

const HOST: &str = "discord.com";
const PORT: &str = "443";

fn host_resolves_outside_guard() -> bool {
    use std::net::ToSocketAddrs;
    format!("{HOST}:{PORT}")
        .to_socket_addrs()
        .map(|i| i.count() > 0)
        .unwrap_or(false)
}

#[cfg(target_os = "macos")]
#[test]
#[ignore = "requires PTY + node + daemon + network + getaddrinfo interpose -- opt-in via --ignored"]
fn learn_mode_allows_default_deny_host() {
    if !host_resolves_outside_guard() {
        eprintln!(
            "SKIP: {HOST}:{PORT} did not resolve outside Stentorian Guard -- \
             cannot run learn-mode passthrough test offline"
        );
        return;
    }

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
    let script = guard_e2e::cargo_workspace_root().join("crates/guard-e2e/harness/connect_evil.js");
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
    cmd.env("STT_GUARD_TEST_DENY_HOST", HOST);
    cmd.env("STT_GUARD_TEST_DENY_PORT", PORT);

    let mut child = pair
        .slave
        .spawn_command(cmd)
        .expect("spawn stt-guard wrap --learn");
    let reader = pair.master.try_clone_reader().expect("clone reader");
    let mut writer = pair.master.take_writer().expect("take writer");
    drop(pair.slave);

    // In learn mode, DefaultDeny hosts are allowed through. After the wrapped
    // process exits, the CLI presents the review prompt for staged hosts.
    // The review menu shows: "  discord.com -- [a]llow / [d]eny / [s]kip / [q]uit > "
    let buf = guard_e2e::read_pty_until(reader, "[a]llow", Duration::from_secs(30)).expect(
        "learn review prompt should appear after node exits -- if this fails, \
             the getaddrinfo interpose may not be working (pre-existing infra issue)",
    );

    // The review prompt proves staging worked -- the host was allowed through
    // during the run and collected for end-of-run review.
    assert!(
        buf.contains("[a]llow"),
        "expected learn review prompt with [a]llow option; PTY output:\n{buf}"
    );

    // Send 's' (skip) to dismiss the review and let the process exit cleanly.
    writer.write_all(b"s\n").expect("write 's' to skip review");
    drop(writer);

    let status = child.wait().expect("wait for stt-guard");
    assert!(
        status.success(),
        "expected exit 0 from learn-mode run (DefaultDeny should be allowed \
         through in learn mode); got: {:?}\nPTY output:\n{buf}",
        status
    );
}
