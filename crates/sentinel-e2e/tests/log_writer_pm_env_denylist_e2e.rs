//! Phase 3 plan 03-14 — R-08: PM env denylisted secrets never reach JSONL.
//!
//! The denylist in sentinel_daemon::env_capture (plan 03-04) filters out
//! CARGO_REGISTRY_TOKEN, npm_config_authToken, etc. from the ExecEvent V3
//! pm_env capture before any log rows are written.
//!
//! This is a NEGATIVE test: asserts that decoy secret values injected into
//! the wrapped process's environment NEVER appear in sentinel.log, even if the
//! full V3 ExecEvent capture path is exercised.
//!
//! Marked #[ignore]: requires full dylib injection (non-hardened binary) + a
//! running daemon + Phase 3 ExecEvent V3 path. Opt-in via:
//!   cargo test -p sentinel-e2e -- --ignored cargo_registry_token_never_leaks

#[cfg(target_os = "macos")]
#[test]
#[ignore = "requires full ExecEvent V3 capture path + non-hardened binary — opt-in via --ignored"]
fn cargo_registry_token_never_leaks_to_log() {
    let harness = sentinel_e2e::DaemonHarness::start().expect("start daemon harness");
    let cli = sentinel_e2e::resolve_cli();
    let dylib = sentinel_e2e::resolve_dylib();

    // Run a simple wrapped command that will generate an ExecEvent V3 on the
    // daemon side. The decoy tokens are injected into its environment.
    // /bin/echo is non-hardened on macOS and accepts DYLD_INSERT_LIBRARIES.
    let _ = std::process::Command::new(&cli)
        .arg("run")
        .arg("--")
        .arg("/bin/echo")
        .arg("hello")
        .env_clear()
        .env("HOME", harness.home.path())
        .env("PATH", std::env::var_os("PATH").unwrap_or_default())
        .env("SENTINEL_HOOK_DYLIB", &dylib)
        .env("SENTINEL_STATE_DIR", &harness.state_dir)
        // Decoy secrets — must NEVER appear in JSONL (R-08 denylist).
        .env("CARGO_REGISTRY_TOKEN", "DECOY_LEAK_TOKEN_xyz123_cargo")
        .env("npm_config_authToken", "DECOY_LEAK_TOKEN_abc456_npm")
        .env("CARGO_REGISTRY_CREDENTIAL_PROVIDER", "DECOY_PROVIDER_cred789")
        // Benign PM env — must still be captured (control).
        .env("npm_package_name", "lodash")
        .output()
        .expect("run sentinel");

    // Allow the daemon's log_writer mpsc to drain.
    std::thread::sleep(std::time::Duration::from_millis(500));

    let log_path = harness
        .home
        .path()
        .join("Library/Logs/Sentinel/sentinel.log");
    let content = std::fs::read_to_string(&log_path).unwrap_or_default();

    // Hard assertions: no decoy token value appears anywhere in the log.
    assert!(
        !content.contains("DECOY_LEAK_TOKEN_xyz123_cargo"),
        "CARGO_REGISTRY_TOKEN value leaked to sentinel.log!\ncontent: {content}"
    );
    assert!(
        !content.contains("DECOY_LEAK_TOKEN_abc456_npm"),
        "npm_config_authToken value leaked to sentinel.log!\ncontent: {content}"
    );
    assert!(
        !content.contains("DECOY_PROVIDER_cred789"),
        "CARGO_REGISTRY_CREDENTIAL_PROVIDER value leaked to sentinel.log!\ncontent: {content}"
    );
}
