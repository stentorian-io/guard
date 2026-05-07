//! crates/sentinel-cli/src/install/launchagent.rs
//!
//! Phase 3 plan 03-09 — LaunchAgent plist generation + launchctl bootstrap.
//! Lifted and generalized from sentinel-daemon::dev_install.
//!
//! Pitfall 6 mitigation: bootstrap is preceded by best-effort `launchctl bootout`
//! to avoid silent label-conflict failure on reinstall.

use std::path::{Path, PathBuf};

use plist::{Dictionary, Value};

pub const LABEL: &str = "com.sentinel.daemon";

pub fn launchagents_dir() -> PathBuf {
    home_dir().join("Library").join("LaunchAgents")
}

pub fn plist_path() -> PathBuf {
    launchagents_dir().join(format!("{LABEL}.plist"))
}

pub fn home_dir() -> PathBuf {
    std::env::var_os("HOME").map(PathBuf::from).unwrap_or_else(|| PathBuf::from("/tmp"))
}

pub fn logs_dir() -> PathBuf {
    home_dir().join("Library").join("Logs").join("Sentinel")
}

pub fn build_plist(daemon_binary: &Path, state_dir: &Path) -> Value {
    let mut dict = Dictionary::new();
    dict.insert("Label".into(), Value::String(LABEL.into()));
    let prog_args = vec![
        Value::String(daemon_binary.to_string_lossy().into()),
        Value::String("serve".into()),
        Value::String("--state-dir".into()),
        Value::String(state_dir.to_string_lossy().into()),
    ];
    dict.insert("ProgramArguments".into(), Value::Array(prog_args));
    dict.insert("RunAtLoad".into(), Value::Boolean(true));
    dict.insert("KeepAlive".into(), Value::Boolean(true));
    let logs = logs_dir();
    dict.insert("StandardOutPath".into(), Value::String(logs.join("daemon.out.log").to_string_lossy().into()));
    dict.insert("StandardErrorPath".into(), Value::String(logs.join("daemon.err.log").to_string_lossy().into()));
    let mut env = Dictionary::new();
    env.insert("RUST_LOG".into(), Value::String("info".into()));
    dict.insert("EnvironmentVariables".into(), Value::Dictionary(env));
    Value::Dictionary(dict)
}

pub fn write_plist(path: &Path, plist: &Value) -> std::io::Result<()> {
    if let Some(parent) = path.parent() { std::fs::create_dir_all(parent)?; }
    plist::to_file_xml(path, plist).map_err(|e| std::io::Error::other(format!("plist write: {e}")))
}

pub fn launchctl_bootstrap(plist_path: &Path) -> std::io::Result<()> {
    // Test-only gate: when SENTINEL_SKIP_LAUNCHCTL is set in the environment,
    // this function returns Ok(()) immediately without invoking launchctl.
    // Used by artifact-only integration tests that drive the install flow under
    // a tempdir HOME without a live launchd GUI session (see plans 03-16, 03-18,
    // 03-19). NEVER set this in production — it is checked once and then ignored.
    if std::env::var_os("SENTINEL_SKIP_LAUNCHCTL").is_some() {
        tracing::debug!(
            plist = %plist_path.display(),
            "SENTINEL_SKIP_LAUNCHCTL set — skipping launchctl bootstrap"
        );
        return Ok(());
    }
    let uid = unsafe { libc::getuid() };
    let domain = format!("gui/{uid}");
    // Pitfall 6: best-effort bootout BEFORE bootstrap to clear stale registration.
    let _ = std::process::Command::new("launchctl")
        .arg("bootout").arg(format!("{domain}/{LABEL}"))
        .status();
    let status = std::process::Command::new("launchctl")
        .arg("bootstrap").arg(&domain).arg(plist_path).status()?;
    if !status.success() {
        return Err(std::io::Error::other(format!("launchctl bootstrap failed: {status}")));
    }
    Ok(())
}

pub fn launchctl_bootout() -> std::io::Result<()> {
    let uid = unsafe { libc::getuid() };
    let domain = format!("gui/{uid}");
    let _ = std::process::Command::new("launchctl")
        .arg("bootout").arg(format!("{domain}/{LABEL}"))
        .status();
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    // NOTE: If these tests flake under parallel execution it is because
    // std::env::set_var / remove_var are not thread-safe when concurrent tests
    // read the same env var. To fix, run with --test-threads=1 or gate with the
    // `serial_test` crate. The workspace does not currently depend on serial_test.

    /// Tier-A: when SENTINEL_SKIP_LAUNCHCTL is set, launchctl_bootstrap must
    /// return Ok(()) even when passed a deliberately non-existent plist path.
    /// A non-existent plist would cause launchctl to reject the call — Ok here
    /// proves the early-return fired before any launchctl invocation.
    #[test]
    fn skip_launchctl_env_var_short_circuits_bootstrap() {
        // Safety: set_var is unsafe in Rust edition ≥ 2024 (multi-threaded risk).
        // This test is single-purpose and the variable is removed immediately after.
        // SENTINEL_SKIP_LAUNCHCTL is only read by launchctl_bootstrap; no other
        // thread in the test process reads it. Acceptable in a unit-test context.
        unsafe { std::env::set_var("SENTINEL_SKIP_LAUNCHCTL", "1") };
        let result = launchctl_bootstrap(&PathBuf::from("/nonexistent/path/test.plist"));
        unsafe { std::env::remove_var("SENTINEL_SKIP_LAUNCHCTL") };
        assert!(result.is_ok(), "expected Ok(()) with SENTINEL_SKIP_LAUNCHCTL set, got: {result:?}");
    }

    /// Tier-B (ignored): when SENTINEL_SKIP_LAUNCHCTL is unset, the function
    /// attempts to invoke launchctl. With a non-existent plist in a non-GUI
    /// session this will fail with Err. Documented here for completeness; marked
    /// #[ignore] because it requires no SENTINEL_SKIP_LAUNCHCTL in the environment
    /// AND depends on launchctl binary availability and GUI-session state.
    #[test]
    #[ignore]
    fn without_skip_env_var_launchctl_is_invoked_and_fails_on_missing_plist() {
        unsafe { std::env::remove_var("SENTINEL_SKIP_LAUNCHCTL") };
        let result = launchctl_bootstrap(&PathBuf::from("/nonexistent/path/test.plist"));
        assert!(result.is_err(), "expected Err without SENTINEL_SKIP_LAUNCHCTL and missing plist");
    }
}
