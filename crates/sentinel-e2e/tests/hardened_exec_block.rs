//! M003-S02: verify that exec of known network-capable hardened-runtime
//! binaries (curl, etc.) is blocked with EACCES, while exec of non-network
//! system utilities (env) is allowed despite being hardened.

use sentinel_e2e::{cargo_target_dir, resolve_cli, resolve_dylib, DaemonHarness};
use std::process::Command;

fn probe_bin() -> std::path::PathBuf {
    cargo_target_dir().join("hardened_exec_probe")
}

fn run_probe(harness: &DaemonHarness, mode: &str) -> std::process::Output {
    let cli = resolve_cli();
    let dylib = resolve_dylib();
    let probe = probe_bin();
    assert!(probe.exists(), "hardened_exec_probe not built at {}", probe.display());

    Command::new(&cli)
        .arg(&probe)
        .arg(mode)
        .env_clear()
        .env("HOME", harness.home.path())
        .env("PATH", std::env::var_os("PATH").unwrap_or_default())
        .env("SENTINEL_HOOK_DYLIB", &dylib)
        .env("SENTINEL_STATE_DIR", &harness.state_dir)
        .output()
        .expect("run sentinel with hardened_exec_probe")
}

/// execve(/usr/bin/curl) must be blocked with EACCES.
#[cfg_attr(not(target_os = "macos"), ignore)]
#[test]
fn exec_curl_blocked() {
    let harness = DaemonHarness::start().expect("start daemon");
    let output = run_probe(&harness, "exec_curl");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(
        !output.status.success(),
        "exec_curl probe should fail (blocked); stdout={stdout}\nstderr={stderr}"
    );
    assert_eq!(
        output.status.code(),
        Some(2),
        "expected exit 2 (EACCES block); got {:?}\nstdout={stdout}\nstderr={stderr}",
        output.status.code()
    );
    assert!(
        stdout.contains("EXEC-BLOCKED-EACCES"),
        "expected EXEC-BLOCKED-EACCES marker; stdout={stdout}"
    );
}

/// posix_spawn(/usr/bin/curl) must be blocked with EACCES.
#[cfg_attr(not(target_os = "macos"), ignore)]
#[test]
fn posix_spawn_curl_blocked() {
    let harness = DaemonHarness::start().expect("start daemon");
    let output = run_probe(&harness, "posix_spawn_curl");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(
        !output.status.success(),
        "posix_spawn_curl probe should fail (blocked); stdout={stdout}\nstderr={stderr}"
    );
    assert_eq!(
        output.status.code(),
        Some(2),
        "expected exit 2 (EACCES block); got {:?}\nstdout={stdout}\nstderr={stderr}",
        output.status.code()
    );
    assert!(
        stdout.contains("POSIX-SPAWN-BLOCKED-EACCES"),
        "expected POSIX-SPAWN-BLOCKED-EACCES marker; stdout={stdout}"
    );
}

/// execve(/usr/bin/env) must NOT be blocked — it's not a network tool.
#[cfg_attr(not(target_os = "macos"), ignore)]
#[test]
fn exec_env_not_blocked() {
    let harness = DaemonHarness::start().expect("start daemon");
    let output = run_probe(&harness, "exec_env");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    // env runs echo, which outputs ENV-EXEC-OK.
    // The exec replaces the process image, so the probe's exit code is
    // whatever env+echo returns (0).
    assert!(
        output.status.success() || stdout.contains("ENV-EXEC-OK"),
        "exec_env should succeed (env is not a blocked binary); stdout={stdout}\nstderr={stderr}"
    );
}
