//! `sentinel unwrap-all` — emergency escape hatch (M004-S05).
//!
//! Immediately disables all enforcement by:
//!   1. Booting out the daemon LaunchAgent (stops new enforcement)
//!   2. Booting out the watchdog LaunchAgent (prevents auto-restart)
//!   3. Removing tracked root state (orphans any active runs)
//!
//! This does NOT uninstall Sentinel — `sentinel setup` will restore
//! enforcement. It is a panic button for when something goes wrong
//! during a wrapped command and the user needs processes to run
//! unimpeded immediately.

use std::path::Path;

use crate::CliError;
use crate::install::launchagent;

pub fn run(_sock: &Path, state_dir: &Path, yes: bool) -> Result<i32, CliError> {
    if !yes {
        if !crate::tty::confirm(
            "This will immediately stop the daemon and watchdog, disabling \
             all enforcement. Active `sentinel wrap` sessions will lose \
             coverage. Continue?",
        )? {
            println!("Aborted.");
            return Ok(0);
        }
    }

    // 1. Bootout watchdog first (prevents it from restarting the daemon).
    match launchagent::launchctl_bootout_watchdog() {
        Ok(()) => println!("  watchdog: stopped"),
        Err(e) => println!("  watchdog: already stopped ({e})"),
    }

    // 2. Bootout daemon.
    match launchagent::launchctl_bootout() {
        Ok(()) => println!("  daemon: stopped"),
        Err(e) => println!("  daemon: already stopped ({e})"),
    }

    // 3. Remove tracked-root state files so orphaned runs don't cause
    //    stale gap detections on next daemon start.
    let runs_dir = state_dir.join("runs");
    if runs_dir.exists() {
        let count = std::fs::read_dir(&runs_dir)
            .map(|entries| entries.count())
            .unwrap_or(0);
        let _ = std::fs::remove_dir_all(&runs_dir);
        println!("  cleared {count} tracked run(s)");
    }

    // 4. Remove the ready-file so `sentinel status` shows daemon-not-running.
    let ready = state_dir.join("daemon.ready");
    let _ = std::fs::remove_file(&ready);

    println!("sentinel: enforcement disabled. Run `sentinel setup` to restore.");
    Ok(0)
}
