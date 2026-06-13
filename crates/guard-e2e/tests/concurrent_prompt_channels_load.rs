#![cfg(target_os = "macos")]

//! v0.3: 32 concurrent stt-guard wrap invocations don't
//! starve the daemon's worker pool.
//!
//! Each `stt-guard wrap -- /bin/sleep 3` causes the CLI to call `PrepareSnapshot`
//! IPC and open a prompt channel (if `is_tty`). With stdin=null (non-TTY), the
//! orchestrator skips the prompt channel open but still dispatches through the
//! daemon worker pool. 32 concurrent dispatches must not exhaust the 16-thread
//! pool (`ACCEPT_QUEUE_DEPTH=64` ensures no connection is dropped).
//!
//! Marked #[ignore]: resource-intensive (32 /bin/sleep children × 3s).
//! Opt-in via: cargo test -p guard-e2e -- --ignored `thirty_two_concurrent`

#[cfg(target_os = "macos")]
#[test]
#[ignore = "resource-intensive (32 concurrent children × 3s) — opt-in via --ignored"]
fn thirty_two_concurrent_guard_runs_succeed() {
    let harness = guard_e2e::DaemonHarness::start().expect("start daemon harness");
    let cli = guard_e2e::resolve_cli();
    let dylib = guard_e2e::resolve_dylib();

    let mut children: Vec<std::process::Child> = Vec::with_capacity(32);
    for i in 0..32usize {
        let child = std::process::Command::new(&cli)
            .arg("wrap")
            .arg("/bin/sleep")
            .arg("3")
            .env_clear()
            .env("HOME", harness.home.path())
            .env("PATH", std::env::var_os("PATH").unwrap_or_default())
            .env("STT_GUARD_HOOK_DYLIB", &dylib)
            .env("STT_GUARD_STATE_DIR", &harness.state_dir)
            .stdin(std::process::Stdio::null()) // non-TTY → skip prompt channel
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .unwrap_or_else(|e| panic!("spawn child {i}: {e}"));
        children.push(child);
    }

    for (i, child) in children.iter_mut().enumerate() {
        let status = child
            .wait()
            .unwrap_or_else(|e| panic!("wait child {i}: {e}"));
        assert!(
            status.success(),
            "child {i} failed: {status:?} — daemon may have exhausted worker pool"
        );
    }
}
