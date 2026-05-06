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
