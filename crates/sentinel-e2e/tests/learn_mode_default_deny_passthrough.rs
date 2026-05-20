//! Learn-mode passthrough: DefaultDeny hosts are allowed and staged.
//!
//! In normal mode `discord.com` triggers DefaultDeny (not in any allowlist).
//! In `--learn` mode the daemon allows the resolution, stages the host for
//! end-of-run review, and the wrapped process resolves successfully.
//!
//! Uses prompt_probe.js with PROBE_CONNECT_AFTER=0 (DNS-only, no TCP connect)
//! which exercises the daemon's Resolve handler directly.
//!
//! Differential companion: learn_mode_curated_deny.rs verifies that
//! BuiltinDeny still blocks in learn mode.
//!
//! Requires PTY because `--learn` gates on stdin_is_tty().
//! Opt-in via: cargo test -p sentinel-e2e -- --ignored learn_mode_allows

use std::io::Write as _;
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
fn learn_mode_allows_default_deny_host() {
    if !host_resolves_outside_sentinel() {
        eprintln!(
            "SKIP: {HOST}:{PORT} did not resolve outside Sentinel — \
             cannot run learn-mode passthrough test offline"
        );
        return;
    }

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
        .join("crates/sentinel-e2e/harness/prompt_probe.js");
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
    cmd.env("PROBE_HOST", HOST);
    cmd.env("PROBE_PORT", PORT);
    cmd.env("PROBE_CONNECT_AFTER", "0");

    let mut child = pair.slave.spawn_command(cmd).expect("spawn sentinel wrap --learn");
    let reader = pair.master.try_clone_reader().expect("clone reader");
    let mut writer = pair.master.take_writer().expect("take writer");
    drop(pair.slave);

    // In learn mode, DefaultDeny hosts are allowed through. The probe does
    // dns.lookup() which triggers the daemon's Resolve handler. After node
    // exits, the CLI presents the review prompt for staged hosts.
    let buf = sentinel_e2e::read_pty_until(
        reader,
        "[a]llow",
        Duration::from_secs(30),
    )
    .expect("learn review prompt should appear after node resolves and exits");

    // The DNS resolution succeeded — probe printed RESOLVE-OK.
    assert!(
        buf.contains("RESOLVE-OK"),
        "expected RESOLVE-OK in learn mode (DefaultDeny should be allowed); PTY output:\n{buf}"
    );

    // The review header should mention the staged host(s).
    assert!(
        buf.contains("host(s) observed"),
        "expected learn review header; PTY output:\n{buf}"
    );

    // Send 's' (skip) to dismiss the review and let the process exit cleanly.
    writer.write_all(b"s\n").expect("write 's' to skip review");
    drop(writer);

    let status = child.wait().expect("wait for sentinel");
    assert!(
        status.success(),
        "expected exit 0 from learn-mode run; got: {:?}",
        status
    );
}
