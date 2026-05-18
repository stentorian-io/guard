//! Auto-spawn the daemon if it's not reachable.
//!
//! Called from `main.rs` before any CLI command that needs IPC. Tries to
//! connect to the socket; if unreachable, locates `sentineld`, spawns it
//! as a background process, and polls until the socket comes up.

use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::CliError;

const SENTINELD_BIN: &str = "sentineld";
const HOMEBREW_SENTINELD: &str = "/opt/homebrew/bin/sentineld";

const RETRY_DELAYS: &[Duration] = &[
    Duration::from_millis(200),
    Duration::from_millis(400),
    Duration::from_millis(800),
    Duration::from_millis(1600),
    Duration::from_millis(3200),
];

fn find_sentineld() -> Result<PathBuf, CliError> {
    if let Some(p) = std::env::var_os("SENTINEL_DAEMON_BIN") {
        let p = PathBuf::from(p);
        if p.exists() {
            return Ok(p);
        }
        return Err(CliError::Other(format!(
            "SENTINEL_DAEMON_BIN={} does not exist",
            p.display()
        )));
    }

    let exe = std::env::current_exe().map_err(|e| CliError::Other(format!("current_exe: {e}")))?;
    if let Some(parent) = exe.parent() {
        let candidate = parent.join(SENTINELD_BIN);
        if candidate.exists() {
            return Ok(candidate);
        }
    }

    let release = PathBuf::from(HOMEBREW_SENTINELD);
    if release.exists() {
        return Ok(release);
    }

    Err(CliError::Other(format!(
        "could not find {SENTINELD_BIN}: tried SENTINEL_DAEMON_BIN, sibling-of-CLI, and {HOMEBREW_SENTINELD}"
    )))
}

fn spawn_daemon(state_dir: &Path) -> Result<(), CliError> {
    let bin = find_sentineld()?;
    let log_dir = crate::install::launchagent::logs_dir();
    let _ = std::fs::create_dir_all(&log_dir);

    let stdout_file = std::fs::File::create(log_dir.join("daemon.out.log"))
        .map_err(|e| CliError::Other(format!("create daemon stdout log: {e}")))?;
    let stderr_file = std::fs::File::create(log_dir.join("daemon.err.log"))
        .map_err(|e| CliError::Other(format!("create daemon stderr log: {e}")))?;

    std::process::Command::new(&bin)
        .arg("serve")
        .arg("--state-dir")
        .arg(state_dir)
        .stdout(stdout_file)
        .stderr(stderr_file)
        .stdin(std::process::Stdio::null())
        .spawn()
        .map_err(|e| {
            CliError::Other(format!(
                "failed to spawn {}: {e}",
                bin.display()
            ))
        })?;

    Ok(())
}

/// Ensure the daemon is reachable. If not, spawn it and wait for the
/// socket to come up. Errors with a clear message if the daemon can't
/// be reached after retries.
pub fn ensure_daemon(sock: &Path, state_dir: &Path) -> Result<(), CliError> {
    if crate::ipc_client::probe_daemon_alive(sock).is_ok() {
        return Ok(());
    }

    eprintln!("sentinel: daemon not running, starting it...");
    spawn_daemon(state_dir)?;

    for delay in RETRY_DELAYS {
        std::thread::sleep(*delay);
        if crate::ipc_client::probe_daemon_alive(sock).is_ok() {
            return Ok(());
        }
    }

    Err(CliError::Other(
        "sentinel: daemon could not be reached after starting it. \
         This is either a bug in Sentinel or something is actively \
         interfering with the daemon process. Check the logs at \
         ~/Library/Logs/Sentinel/daemon.err.log for details."
            .into(),
    ))
}
