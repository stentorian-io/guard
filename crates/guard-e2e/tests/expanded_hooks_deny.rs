//! M003-S01-T06: verify that exfiltration via send() and write()-to-socket
//! is blocked by the expanded hook surface.
//!
//! Also verifies that write() to regular files and pipes is NOT affected
//! (no false positives from the write/writev interpose).
//!
//! Each sub-test invokes the `expanded_hooks_probe` binary under Stentorian Guard
//! with a specific mode and asserts the expected outcome.

use guard_e2e::{DaemonHarness, cargo_target_dir, resolve_cli, resolve_dylib};
use std::process::Command;

const DENY_HOST: &str = "discord.com";
const DENY_PORT: &str = "443";

fn deny_target_resolves() -> bool {
    use std::net::ToSocketAddrs;
    format!("{DENY_HOST}:{DENY_PORT}")
        .to_socket_addrs()
        .map(|i| i.count() > 0)
        .unwrap_or(false)
}

fn probe_bin() -> std::path::PathBuf {
    cargo_target_dir().join("expanded_hooks_probe")
}

fn run_probe(harness: &DaemonHarness, mode: &str) -> std::process::Output {
    let cli = resolve_cli();
    let dylib = resolve_dylib();
    let probe = probe_bin();
    assert!(
        probe.exists(),
        "expanded_hooks_probe not built at {}",
        probe.display()
    );

    Command::new(&cli)
        .arg("wrap")
        .arg(&probe)
        .arg(mode)
        .env_clear()
        .env("HOME", harness.home.path())
        .env("PATH", std::env::var_os("PATH").unwrap_or_default())
        .env("STT_GUARD_HOOK_DYLIB", &dylib)
        .env("STT_GUARD_STATE_DIR", &harness.state_dir)
        .env("STT_GUARD_TEST_DENY_HOST", DENY_HOST)
        .env("STT_GUARD_TEST_DENY_PORT", DENY_PORT)
        .output()
        .expect("run stt-guard with expanded_hooks_probe")
}

/// send() on a connected socket to a non-allowed host is denied at connect time.
#[cfg_attr(not(target_os = "macos"), ignore)]
#[test]
fn send_to_non_allowed_host_denied() {
    if !deny_target_resolves() {
        eprintln!("SKIP: {DENY_HOST} not resolvable (offline?)");
        return;
    }
    let harness = DaemonHarness::start().expect("start daemon");
    let output = run_probe(&harness, "send");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(
        !output.status.success(),
        "send probe should fail (denied); stdout={stdout}\nstderr={stderr}"
    );
    assert_eq!(
        output.status.code(),
        Some(2),
        "expected exit 2 (EHOSTUNREACH deny); got {:?}\nstdout={stdout}\nstderr={stderr}",
        output.status.code()
    );
    assert!(
        stdout.contains("DENIED")
            || stdout.contains("EHOSTUNREACH")
            || stdout.contains("DNS-DENIED"),
        "expected denial marker in output; stdout={stdout}"
    );
}

/// write() on a connected socket to a non-allowed host is denied at connect time.
#[cfg_attr(not(target_os = "macos"), ignore)]
#[test]
fn write_socket_to_non_allowed_host_denied() {
    if !deny_target_resolves() {
        eprintln!("SKIP: {DENY_HOST} not resolvable (offline?)");
        return;
    }
    let harness = DaemonHarness::start().expect("start daemon");
    let output = run_probe(&harness, "write_socket");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(
        !output.status.success(),
        "write_socket probe should fail (denied); stdout={stdout}\nstderr={stderr}"
    );
    assert_eq!(
        output.status.code(),
        Some(2),
        "expected exit 2 (EHOSTUNREACH deny); got {:?}\nstdout={stdout}\nstderr={stderr}",
        output.status.code()
    );
}

// libc syscall(SYS_CONNECT, ...) bypass test: DEFERRED.
// libc's syscall(int, ...) uses C variadic calling convention. On aarch64
// macOS, variadic args go on the stack — a non-variadic Rust interpose
// function cannot reliably extract them. Rust's c_variadic feature is
// unstable. Unknown native binaries containing raw syscall instruction bytes
// are handled by exec-time T3 fail-closed classification instead.

/// write() to a regular file must NOT be affected by the hook.
#[cfg_attr(not(target_os = "macos"), ignore)]
#[test]
fn write_file_not_affected() {
    let harness = DaemonHarness::start().expect("start daemon");
    let output = run_probe(&harness, "write_file");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(
        output.status.success(),
        "write_file should succeed (not a socket); stdout={stdout}\nstderr={stderr}"
    );
    assert!(
        stdout.contains("WRITE-FILE-OK"),
        "expected WRITE-FILE-OK; stdout={stdout}"
    );
}

/// write() to a pipe must NOT be affected by the hook.
#[cfg_attr(not(target_os = "macos"), ignore)]
#[test]
fn write_pipe_not_affected() {
    let harness = DaemonHarness::start().expect("start daemon");
    let output = run_probe(&harness, "write_pipe");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(
        output.status.success(),
        "write_pipe should succeed (not a socket); stdout={stdout}\nstderr={stderr}"
    );
    assert!(
        stdout.contains("WRITE-PIPE-OK"),
        "expected WRITE-PIPE-OK; stdout={stdout}"
    );
}
