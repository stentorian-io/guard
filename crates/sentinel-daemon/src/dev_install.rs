//! Generate ~/Library/LaunchAgents/com.sentinel.daemon.plist via the `plist` crate.
//!
//! Per .planning/phases/01-foundations-hook-hello-world/01-RESEARCH.md "Don't
//! Hand-Roll" — no string-templated XML.

use plist::{Dictionary, Value};
use std::path::{Path, PathBuf};

pub const LABEL: &str = "com.sentinel.daemon";

pub fn launch_agent_plist_path() -> PathBuf {
    let home = std::env::var_os("HOME").expect("HOME");
    PathBuf::from(home)
        .join("Library/LaunchAgents")
        .join(format!("{LABEL}.plist"))
}

pub fn logs_dir() -> PathBuf {
    let home = std::env::var_os("HOME").expect("HOME");
    PathBuf::from(home).join("Library/Logs/Sentinel")
}

/// Build the plist Value tree for the LaunchAgent.
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
    dict.insert(
        "StandardOutPath".into(),
        Value::String(logs.join("daemon.out.log").to_string_lossy().into()),
    );
    dict.insert(
        "StandardErrorPath".into(),
        Value::String(logs.join("daemon.err.log").to_string_lossy().into()),
    );
    let mut env = Dictionary::new();
    env.insert("RUST_LOG".into(), Value::String("info".into()));
    dict.insert("EnvironmentVariables".into(), Value::Dictionary(env));
    Value::Dictionary(dict)
}

/// Write the plist to `~/Library/LaunchAgents/`. Creates the parent dir if missing.
pub fn write(daemon_binary: &Path, state_dir: &Path) -> std::io::Result<PathBuf> {
    let path = launch_agent_plist_path();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let logs = logs_dir();
    std::fs::create_dir_all(&logs)?;
    let value = build_plist(daemon_binary, state_dir);
    plist::to_file_xml(&path, &value)
        .map_err(|e| std::io::Error::other(format!("plist write: {e}")))?;
    Ok(path)
}

/// Run `launchctl bootstrap gui/$UID <plist>` to load the agent.
pub fn launchctl_bootstrap(plist_path: &Path) -> std::io::Result<()> {
    let uid = unsafe { libc::getuid() };
    let domain = format!("gui/{uid}");
    let status = std::process::Command::new("launchctl")
        .arg("bootstrap")
        .arg(&domain)
        .arg(plist_path)
        .status()?;
    if !status.success() {
        return Err(std::io::Error::other(format!(
            "launchctl bootstrap failed: {status}"
        )));
    }
    Ok(())
}
