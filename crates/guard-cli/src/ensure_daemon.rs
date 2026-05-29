//! Install gate and daemon connectivity check.
//!
//! Called from `main.rs` before any CLI command that needs IPC. Verifies the
//! hardened installation is present, then checks daemon reachability.
//! Linux development mode starts a sibling daemon binary. A Linux system-state
//! directory is treated as a hardened install and must pass the install gate.

use std::path::Path;
#[cfg(target_os = "linux")]
use std::path::PathBuf;
#[cfg(target_os = "linux")]
use std::process::{Command, Stdio};
use std::time::Duration;

use crate::CliError;

const RETRY_DELAYS: &[Duration] = &[
    Duration::from_millis(200),
    Duration::from_millis(400),
    Duration::from_millis(800),
    Duration::from_millis(1600),
    Duration::from_millis(3200),
];

/// Verify or start the daemon path appropriate for the current platform.
/// System installs require the hardened gate; Linux user-state paths remain
/// development mode.
///
/// # Errors
///
/// Returns an error when the install gate fails or the daemon cannot be made
/// reachable.
pub fn ensure_daemon(sock: &Path, state_dir: &Path) -> Result<(), CliError> {
    #[cfg(target_os = "linux")]
    {
        ensure_linux_daemon(sock, state_dir)
    }

    #[cfg(not(target_os = "linux"))]
    {
        let _ = state_dir;
        ensure_installed_daemon(sock)
    }
}

#[cfg(target_os = "linux")]
fn ensure_linux_daemon(sock: &Path, state_dir: &Path) -> Result<(), CliError> {
    if guard_core::paths::is_system_install(state_dir) {
        return ensure_installed_daemon(sock);
    }

    ensure_linux_development_daemon(sock, state_dir)
}

fn ensure_installed_daemon(sock: &Path) -> Result<(), CliError> {
    require_installed()?;

    if crate::ipc_client::probe_daemon_alive(sock).is_ok() {
        return Ok(());
    }

    // Daemon is installed but not responding; give the platform service
    // manager a moment to restart it after a crash.
    eprintln!("stt-guard: waiting for daemon...");
    for delay in RETRY_DELAYS {
        std::thread::sleep(*delay);
        if crate::ipc_client::probe_daemon_alive(sock).is_ok() {
            return Ok(());
        }
    }

    Err(CliError::Other(
        "stt-guard: daemon is installed but not responding. \
         Check the service manager logs for details."
            .into(),
    ))
}

#[cfg(target_os = "linux")]
fn ensure_linux_development_daemon(sock: &Path, state_dir: &Path) -> Result<(), CliError> {
    if crate::ipc_client::probe_daemon_alive(sock).is_ok() {
        return Ok(());
    }

    let daemon = development_daemon_binary()?;
    std::fs::create_dir_all(state_dir).map_err(|err| {
        CliError::Other(format!(
            "create Linux development state dir {}: {err}",
            state_dir.display()
        ))
    })?;

    eprintln!(
        "stt-guard: starting Linux development daemon at {}",
        state_dir.display()
    );
    Command::new(&daemon)
        .arg("serve")
        .arg("--state-dir")
        .arg(state_dir)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|err| CliError::Other(format!("start {}: {err}", daemon.display())))?;

    for delay in RETRY_DELAYS {
        std::thread::sleep(*delay);
        if crate::ipc_client::probe_daemon_alive(sock).is_ok() {
            return Ok(());
        }
    }

    Err(CliError::Other(format!(
        "stt-guard: Linux development daemon did not become ready at {}",
        sock.display()
    )))
}

#[cfg(target_os = "linux")]
fn development_daemon_binary() -> Result<PathBuf, CliError> {
    let current_exe =
        std::env::current_exe().map_err(|err| CliError::Other(format!("current_exe: {err}")))?;
    let daemon = daemon_binary_next_to_current_exe(&current_exe)?;
    if daemon.exists() {
        return Ok(daemon);
    }

    Err(CliError::Other(format!(
        "stt-guard-daemon not found at {}. Build the workspace before using Linux development mode.",
        daemon.display()
    )))
}

#[cfg(target_os = "linux")]
fn daemon_binary_next_to_current_exe(current_exe: &Path) -> Result<PathBuf, CliError> {
    let dir = current_exe.parent().ok_or_else(|| {
        CliError::Other(format!(
            "cannot determine binary directory from {}",
            current_exe.display()
        ))
    })?;

    Ok(dir.join(guard_core::paths::DAEMON_BIN))
}

/// Check that the hardened installation exists. Returns an actionable error
/// message if not.
///
/// Skipped when `STT_GUARD_STATE_DIR` is set — the caller is explicitly
/// managing a non-system daemon (dev/test harness).
///
/// # Errors
///
/// Returns an error when the hardened installation is missing or unhealthy.
pub fn require_installed() -> Result<(), CliError> {
    if std::env::var_os(guard_core::paths::ENV_STATE_DIR).is_some() {
        return Ok(());
    }
    let health = crate::install::system::install_health();
    if !health.is_healthy() {
        return Err(CliError::Other(health.error_message()));
    }
    Ok(())
}

#[cfg(test)]
#[cfg(target_os = "linux")]
mod tests {
    use super::daemon_binary_next_to_current_exe;
    use std::path::{Path, PathBuf};

    #[test]
    fn linux_development_daemon_binary_lives_next_to_cli() {
        let daemon = daemon_binary_next_to_current_exe(Path::new("/tmp/bin/stt-guard")).unwrap();

        assert_eq!(daemon, PathBuf::from("/tmp/bin/stt-guard-daemon"));
    }
}
