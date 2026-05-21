//! Auto-spawn the daemon if it's not reachable.
//!
//! Called from `main.rs` before any CLI command that needs IPC. Tries to
//! connect to the socket; if unreachable, locates `stt-guard-daemon`, spawns it
//! as a background process, and polls until the socket comes up.

use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::CliError;

const STT_GUARD_DAEMON_BIN: &str = "stt-guard-daemon";
const HOMEBREW_STT_GUARD_DAEMON: &str = "/opt/homebrew/bin/stt-guard-daemon";

const RETRY_DELAYS: &[Duration] = &[
    Duration::from_millis(200),
    Duration::from_millis(400),
    Duration::from_millis(800),
    Duration::from_millis(1600),
    Duration::from_millis(3200),
];

fn find_guard_daemon() -> Result<PathBuf, CliError> {
    let exe = std::env::current_exe().map_err(|e| CliError::Other(format!("current_exe: {e}")))?;
    if let Some(parent) = exe.parent() {
        let candidate = parent.join(STT_GUARD_DAEMON_BIN);
        if candidate.exists() {
            return Ok(candidate);
        }
    }

    let release = PathBuf::from(HOMEBREW_STT_GUARD_DAEMON);
    if release.exists() {
        return Ok(release);
    }

    Err(CliError::Other(format!(
        "could not find {STT_GUARD_DAEMON_BIN}: tried sibling-of-CLI and {HOMEBREW_STT_GUARD_DAEMON}"
    )))
}

fn spawn_daemon(state_dir: &Path) -> Result<(), CliError> {
    let bin = find_guard_daemon()?;
    let log_dir = crate::install::launchagent::logs_dir();
    let _ = std::fs::create_dir_all(&log_dir);

    let stdout_file = std::fs::File::create(log_dir.join("daemon.out.log"))
        .map_err(|e| CliError::Other(format!("create daemon stdout log: {e}")))?;
    let stderr_file = std::fs::File::create(log_dir.join("stt-guard-daemon.err.log"))
        .map_err(|e| CliError::Other(format!("create daemon stderr log: {e}")))?;

    std::process::Command::new(&bin)
        .arg("serve")
        .arg("--state-dir")
        .arg(state_dir)
        .stdout(stdout_file)
        .stderr(stderr_file)
        .stdin(std::process::Stdio::null())
        .spawn()
        .map_err(|e| CliError::Other(format!("failed to spawn {}: {e}", bin.display())))?;

    Ok(())
}

/// Ensure the daemon is reachable. If not, spawn it and wait for the
/// socket to come up. Errors with a clear message if the daemon can't
/// be reached after retries.
pub fn ensure_daemon(sock: &Path, state_dir: &Path) -> Result<(), CliError> {
    if crate::ipc_client::probe_daemon_alive(sock).is_ok() {
        return Ok(());
    }

    eprintln!("stt-guard: daemon not running, starting it...");
    spawn_daemon(state_dir)?;

    for delay in RETRY_DELAYS {
        std::thread::sleep(*delay);
        if crate::ipc_client::probe_daemon_alive(sock).is_ok() {
            return Ok(());
        }
    }

    Err(CliError::Other(
        "stt-guard: daemon could not be reached after starting it. \
         This is either a bug in Stentorian Guard or something is actively \
         interfering with the daemon process. Check the logs at \
         ~/Library/Logs/Stentorian Guard/stt-guard-daemon.err.log for details."
            .into(),
    ))
}
