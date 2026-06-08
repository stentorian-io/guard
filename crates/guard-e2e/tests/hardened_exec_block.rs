#![cfg(target_os = "macos")]

//! Verify issue #1 phase 1 exec-time layered enforcement.

use guard_e2e::{DaemonHarness, cargo_target_dir, resolve_cli, resolve_dylib};
use std::process::Command;

fn probe_bin() -> std::path::PathBuf {
    cargo_target_dir().join("hardened_exec_probe")
}

fn run_probe(harness: &DaemonHarness, mode: &str) -> std::process::Output {
    let cli = resolve_cli();
    let dylib = resolve_dylib();
    let probe = probe_bin();
    assert!(
        probe.exists(),
        "hardened_exec_probe not built at {}",
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
        .output()
        .expect("run stt-guard with hardened_exec_probe")
}

/// execve(/usr/bin/curl) must be blocked with EACCES.
#[cfg_attr(not(target_os = "macos"), ignore = "macOS-only test")]
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

/// `posix_spawn(/usr/bin/curl)` must be blocked with EACCES.
#[cfg_attr(not(target_os = "macos"), ignore = "macOS-only test")]
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

/// execve(/usr/bin/env) must now be blocked because phase 1 treats all
/// hardened-runtime exec targets as T0.
#[cfg_attr(not(target_os = "macos"), ignore = "macOS-only test")]
#[test]
fn exec_env_blocked_as_t0_hardened_runtime() {
    let harness = DaemonHarness::start().expect("start daemon");
    let output = run_probe(&harness, "exec_env");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(
        !output.status.success(),
        "exec_env probe should fail (blocked); stdout={stdout}\nstderr={stderr}"
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

/// Fat/universal Mach-O binaries are T0-blocked until multi-slice scanning
/// lands.
#[cfg_attr(not(target_os = "macos"), ignore = "macOS-only test")]
#[test]
fn synthetic_fat_macho_blocked() {
    let harness = DaemonHarness::start().expect("start daemon");
    let output = run_probe(&harness, "exec_synthetic_fat");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(
        !output.status.success(),
        "synthetic fat probe should fail (blocked); stdout={stdout}\nstderr={stderr}"
    );
    assert_eq!(
        output.status.code(),
        Some(2),
        "expected exit 2 (EACCES block); got {:?}\nstdout={stdout}\nstderr={stderr}",
        output.status.code()
    );
    assert!(
        stdout.contains("SYNTHETIC-FAT-BLOCKED-EACCES"),
        "expected SYNTHETIC-FAT-BLOCKED-EACCES marker; stdout={stdout}"
    );
}

/// A native thin Mach-O containing raw syscall bytes is T3. Direct exec-family
/// calls cannot safely hand tracing to the daemon, so they fail closed.
#[cfg_attr(not(target_os = "macos"), ignore = "macOS-only test")]
#[test]
fn synthetic_syscall_macho_exec_fails_closed() {
    let harness = DaemonHarness::start().expect("start daemon");
    let output = run_probe(&harness, "exec_synthetic_syscall");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(
        !output.status.success(),
        "synthetic syscall probe should be blocked; stdout={stdout}\nstderr={stderr}"
    );
    assert_eq!(
        output.status.code(),
        Some(2),
        "expected exit 2 (EACCES block); got {:?}\nstdout={stdout}\nstderr={stderr}",
        output.status.code()
    );
    assert!(
        stdout.contains("SYNTHETIC-SYSCALL-BLOCKED-EACCES"),
        "expected SYNTHETIC-SYSCALL-BLOCKED-EACCES marker; stdout={stdout}\nstderr={stderr}"
    );
}

/// T3 `posix_spawn` fails closed before child creation.
#[cfg_attr(not(target_os = "macos"), ignore = "macOS-only test")]
#[test]
fn synthetic_syscall_macho_posix_spawn_with_attrs_fails_closed() {
    let harness = DaemonHarness::start().expect("start daemon");
    let output = run_probe(&harness, "posix_spawn_synthetic_syscall_attr");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(
        !output.status.success(),
        "synthetic syscall posix_spawn attr probe should fail; stdout={stdout}\nstderr={stderr}"
    );
    assert_eq!(
        output.status.code(),
        Some(2),
        "expected exit 2 (ENOTSUP fail-closed); got {:?}\nstdout={stdout}\nstderr={stderr}",
        output.status.code()
    );
    assert!(
        stdout.contains("SYNTHETIC-SYSCALL-POSIX-SPAWN-ATTR-ENOTSUP"),
        "expected SYNTHETIC-SYSCALL-POSIX-SPAWN-ATTR-ENOTSUP marker; stdout={stdout}\nstderr={stderr}"
    );
}
