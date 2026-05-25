#![cfg(target_os = "linux")]

use std::path::{Path, PathBuf};
use std::process::Command;

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
