//! Install gate and daemon connectivity check.
//!
//! Called from `main.rs` before any CLI command that needs IPC. Verifies the
//! hardened installation is present, then checks daemon reachability.
//! The old auto-spawn behaviour is removed — users must run `stt-guard install`.

use std::path::Path;
use std::time::Duration;

use crate::CliError;

const RETRY_DELAYS: &[Duration] = &[
    Duration::from_millis(200),
    Duration::from_millis(400),
    Duration::from_millis(800),
    Duration::from_millis(1600),
    Duration::from_millis(3200),
];

/// Verify the hardened installation is in place and the daemon is reachable.
/// Refuses to proceed if `stt-guard install` has not been run.
pub fn ensure_daemon(sock: &Path, _state_dir: &Path) -> Result<(), CliError> {
    require_installed()?;

    if crate::ipc_client::probe_daemon_alive(sock).is_ok() {
        return Ok(());
    }

    // Daemon is installed but not responding — give it a moment (launchd
    // may be restarting it after a crash).
    eprintln!("stt-guard: waiting for daemon...");
    for delay in RETRY_DELAYS {
        std::thread::sleep(*delay);
        if crate::ipc_client::probe_daemon_alive(sock).is_ok() {
            return Ok(());
        }
    }

    Err(CliError::Other(
        "stt-guard: daemon is installed but not responding. \
         Check /var/log/stt-guard/daemon.err.log for details."
            .into(),
    ))
}

/// Check that the hardened installation exists. Returns an actionable error
/// message if not.
pub fn require_installed() -> Result<(), CliError> {
    if !crate::install::system::is_installed() {
        return Err(CliError::Other(
            "Stentorian Guard is not installed. Run: sudo stt-guard install".into(),
        ));
    }
    Ok(())
}
