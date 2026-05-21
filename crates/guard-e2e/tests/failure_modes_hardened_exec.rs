//! Issue #1 phase 1 closes the old hardened-runtime coverage gap by blocking
//! T0 exec targets before DYLD stripping can occur.

use std::process::Command;

use guard_e2e::{DaemonHarness, cargo_target_dir, resolve_cli, resolve_dylib};

#[cfg_attr(not(target_os = "macos"), ignore)]
#[test]
fn hardened_runtime_exec_is_blocked_before_coverage_gap() {
    let cli = resolve_cli();
    let dylib = resolve_dylib();
    let harness = DaemonHarness::start().expect("start daemon");

    // Start Stentorian Guard on a non-hardened helper so the hook loads, then have the
    // helper exec an Apple-signed hardened binary. Starting Stentorian Guard directly
    // on the hardened binary strips DYLD before the hook can report anything.
    let probe = cargo_target_dir().join("hardened_exec_probe");
    assert!(
        probe.exists(),
        "hardened_exec_probe not built at {}",
        probe.display()
    );

    let out = Command::new(&cli)
        .arg("wrap")
        .arg(&probe)
        .arg("posix_spawn_env_delayed")
        .env_clear()
        .env("HOME", harness.home.path())
        .env("PATH", std::env::var_os("PATH").unwrap_or_default())
        .env("STT_GUARD_HOOK_DYLIB", &dylib)
        .env("STT_GUARD_STATE_DIR", &harness.state_dir)
        .output()
        .expect("run stt-guard");

    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        !out.status.success(),
        "hardened-runtime spawn should be blocked; stdout={stdout}\nstderr={stderr}"
    );
    assert_eq!(
        out.status.code(),
        Some(2),
        "expected exit 2 (EACCES block); got {:?}\nstdout={stdout}\nstderr={stderr}",
        out.status.code()
    );
    assert!(
        stdout.contains("POSIX-SPAWN-BLOCKED-EACCES"),
        "expected POSIX-SPAWN-BLOCKED-EACCES marker; stdout={stdout}\nstderr={stderr}"
    );
}
