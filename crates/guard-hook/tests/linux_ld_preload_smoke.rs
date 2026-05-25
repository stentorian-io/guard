#![cfg(target_os = "linux")]

use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

fn built_hook_so() -> PathBuf {
    let mut dir = std::env::current_exe().expect("current test binary path");
    while dir.pop() {
        let candidate = dir.join("libguard_hook.so");
        if candidate.exists() {
            return candidate;
        }
    }
    panic!("libguard_hook.so must be built before Linux LD_PRELOAD smoke tests run");
}

#[test]
fn ld_preload_loads_hook_constructor() {
    let hook = built_hook_so();
    let tempdir = tempfile::tempdir().expect("tempdir");
    let marker = tempdir.path().join("hook-loaded");

    let status = Command::new(Path::new("/bin/true"))
        .env("LD_PRELOAD", &hook)
        .env("STT_GUARD_TEST_MARKER", &marker)
        .status()
        .expect("spawn /bin/true with LD_PRELOAD");

    assert!(status.success(), "/bin/true should exit successfully");
    assert!(
        marker.exists(),
        "hook constructor marker was not written; LD_PRELOAD did not load {}",
        hook.display()
    );
}

#[test]
fn ld_preload_fail_closes_connect_without_snapshot() {
    let hook = built_hook_so();
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind listener");
    listener
        .set_nonblocking(true)
        .expect("listener nonblocking");
    let target = listener.local_addr().expect("listener addr");
    let tempdir = tempfile::tempdir().expect("tempdir");
    let marker = tempdir.path().join("hook-loaded-connect");

    let status = Command::new(std::env::current_exe().expect("current test binary"))
        .args([
            "--ignored",
            "--exact",
            "linux_connect_child_helper",
            "--nocapture",
        ])
        .env("LD_PRELOAD", &hook)
        .env("STT_GUARD_TEST_MARKER", &marker)
        .env("STT_GUARD_CONNECT_TARGET", target.to_string())
        .status()
        .expect("spawn connect helper with LD_PRELOAD");

    assert!(status.success(), "connect helper should observe denial");
    assert!(
        marker.exists(),
        "hook constructor marker was not written; LD_PRELOAD did not load {}",
        hook.display()
    );
    assert!(
        listener.accept().is_err(),
        "listener should not receive a connection when hook fail-closes connect"
    );
}

#[test]
#[ignore = "spawned by ld_preload_fail_closes_connect_without_snapshot"]
fn linux_connect_child_helper() {
    let target = std::env::var("STT_GUARD_CONNECT_TARGET").expect("target env");
    let addr = target.parse().expect("target socket addr");

    if std::net::TcpStream::connect_timeout(&addr, Duration::from_millis(500)).is_ok() {
        panic!("connect unexpectedly succeeded under fail-closed hook");
    }
}
