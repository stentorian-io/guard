//! crates/sentinel-cli/src/uninstall.rs
//!
//! Phase 07 plan 02 (D-15): factor the v0.1 monolithic `run_uninstall` into
//! per-component helpers (`components::remove_daemon`, `remove_shell`,
//! `remove_state_and_logs`) plus a top-level `run_remove` dispatch keyed on
//! `Option<SetupTarget>`. The v0.1 `run_uninstall(sock, state_dir, force)`
//! entrypoint is preserved as a back-compat shim that forwards to
//! `run_remove(sock, state_dir, None, force)` so the existing
//! `Cmd::Uninstall { force }` arm in main.rs continues working through this
//! wave; Plan 04 deletes both the arm and the shim when the new parser
//! ships.
//!
//! D-15 WARNING-5: each component helper now issues
//! `delete_install_artifacts_request(sock, kinds)` after its on-disk teardown
//! so the install_artifacts table reflects reality even after a per-target
//! remove. Best-effort: if the IPC fails (e.g. daemon already shut down) we
//! don't fail the whole `setup --remove` sequence.
//!
//! Pitfall 5: bootout → 250ms sleep → state-dir delete order is preserved by
//! the `run_remove(target=None)` body (`remove_shell` first while daemon is
//! alive, then `remove_daemon` triggers bootout, then `remove_state_and_logs`
//! deletes the DB after the post-bootout sleep).

use std::path::Path;

use crate::CliError;

/// Phase 07 — per-target dispatch for `setup [target] --remove` / `setup
/// [target]`. Plan 04 will move this enum to `cli.rs` (so clap can derive on
/// it directly) and re-export it from this module; until then it lives here
/// so the file compiles standalone.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SetupTarget {
    Daemon,
    Shell,
}

/// Phase 07 D-15: per-target + global remove. `target=None` is the global
/// path (today's full uninstall body); `Some(Daemon)` strips daemon
/// artifacts only; `Some(Shell)` strips shell artifacts only.
///
/// Confirmation gate: when `yes == false`, calls `tty::confirm` (which
/// rejects non-TTY stdin per WR-04). When `yes == true`, skips the prompt.
pub fn run_remove(
    sock: &Path,
    state_dir: &Path,
    target: Option<SetupTarget>,
    yes: bool,
) -> Result<i32, CliError> {
    if !yes {
        let prompt = match target {
            None => "This will remove the daemon, all rules, all logs, all trust entries, and all shell aliases. Continue?".to_string(),
            Some(SetupTarget::Daemon) => "This will remove the daemon LaunchAgent and plist (preserving rules, logs, and shell aliases). Continue?".to_string(),
            Some(SetupTarget::Shell)  => "This will remove the Sentinel shell marker blocks (preserving daemon, rules, and logs). Continue?".to_string(),
        };
        if !crate::tty::confirm(&prompt)? {
            println!("Aborted.");
            return Ok(0);
        }
    }
    match target {
        None => {
            // Global remove: order matters (Pitfall 5).
            // Step 1: shell artifacts first (daemon still alive — IPC succeeds).
            components::remove_shell(sock, state_dir)?;
            // Step 2: daemon — issues launchctl bootout + 250ms sleep + plist
            // delete. The daemon is still alive when remove_daemon's
            // delete_install_artifacts IPC fires (the 250ms sleep is the
            // post-bootout buffer that lets the daemon persist before its
            // process exits).
            components::remove_daemon(sock, state_dir)?;
            // Step 3: state_dir + log_dir. The daemon may already have exited
            // by now; the IPC inside this helper is best-effort. The state_dir
            // delete is the last destructive step (Pitfall 5: must follow the
            // post-bootout sleep so the WAL is closed).
            components::remove_state_and_logs(sock, state_dir)?;
            println!("Uninstalled. (`brew uninstall sentinel` removes the binary.)");
            Ok(0)
        }
        Some(SetupTarget::Daemon) => {
            components::remove_daemon(sock, state_dir)?;
            println!("Removed daemon LaunchAgent + plist.");
            Ok(0)
        }
        Some(SetupTarget::Shell) => {
            components::remove_shell(sock, state_dir)?;
            println!("Removed shell marker blocks.");
            Ok(0)
        }
    }
}

/// Back-compat shim for the v0.1 `Cmd::Uninstall { force }` arm. Plan 04
/// deletes the old arm and this shim along with it. For this wave, the shim
/// preserves `cargo build` green and existing v0.1 e2e tests.
pub fn run_uninstall(sock: &Path, state_dir: &Path, force: bool) -> Result<i32, CliError> {
    run_remove(sock, state_dir, None, force)
}

pub mod components {
    use std::path::Path;

    use crate::install::{artifacts, init_script, launchagent, marker_block};
    use crate::CliError;

    /// Daemon-only removal: launchctl bootout + 250ms sleep + plist file
    /// delete + install_artifacts cleanup for `["launchagent", "binary"]`.
    /// Reads install_artifacts and processes only `artifact_kind ==
    /// "launchagent"` (and `"binary"` which is informational/skipped per
    /// D-65 since brew owns the binary lifecycle).
    pub fn remove_daemon(sock: &Path, state_dir: &Path) -> Result<(), CliError> {
        let db_path = state_dir.join("sentinel.db");
        let arts = artifacts::read_artifacts(sock, &db_path).unwrap_or_default();

        // 1. launchctl bootout (Pitfall 6: ignore non-zero — duplicate bootouts
        //    are benign; SENTINEL_SKIP_LAUNCHCTL would short-circuit this in
        //    test environments).
        let _ = launchagent::launchctl_bootout();

        // 2. 250ms sleep — Pitfall 5: bootout is async; let the daemon tear
        //    down (closing its WAL) before later steps delete the DB.
        std::thread::sleep(std::time::Duration::from_millis(250));

        // 3. Delete plist file(s) listed in artifacts as `launchagent` kind.
        for art in &arts {
            if art.artifact_kind == "launchagent" {
                let _ = std::fs::remove_file(&art.target_path);
            }
            // "binary" rows are informational (D-65; brew owns the binary).
            // Skip — but we still clear the row below in the IPC call.
        }

        // 4. D-15 WARNING-5: clear install_artifacts rows for the kinds we
        //    just removed. Best-effort — the daemon may already be shutting
        //    down (still alive in per-target path; possibly down by the
        //    global-remove sequence's later steps).
        let _ = crate::ipc_client::delete_install_artifacts_request(
            sock,
            vec!["launchagent".into(), "binary".into()],
        );
        Ok(())
    }

    /// Shell-only removal: strip marker_block + init_script artifacts.
    /// Preserves daemon, rules, logs, state_dir.
    pub fn remove_shell(sock: &Path, state_dir: &Path) -> Result<(), CliError> {
        let db_path = state_dir.join("sentinel.db");
        let arts = artifacts::read_artifacts(sock, &db_path).unwrap_or_default();
        for art in &arts {
            match art.artifact_kind.as_str() {
                "marker_block" => {
                    let _ = marker_block::strip(Path::new(&art.target_path));
                }
                "init_script" => {
                    let _ = init_script::strip(Path::new(&art.target_path));
                }
                _ => {}
            }
        }
        // D-15 WARNING-5: clear install_artifacts rows for the kinds we just
        // stripped. Best-effort cleanup (same rationale as remove_daemon).
        let _ = crate::ipc_client::delete_install_artifacts_request(
            sock,
            vec!["marker_block".into(), "init_script".into()],
        );
        Ok(())
    }

    /// Global-remove tail: state_dir + log_dir removal. Must run AFTER
    /// `remove_daemon` so the daemon's WAL is closed before we delete the DB.
    pub fn remove_state_and_logs(sock: &Path, state_dir: &Path) -> Result<(), CliError> {
        let db_path = state_dir.join("sentinel.db");
        let arts = artifacts::read_artifacts(sock, &db_path).unwrap_or_default();
        for art in &arts {
            match art.artifact_kind.as_str() {
                "log_dir" => {
                    let _ = std::fs::remove_dir_all(&art.target_path);
                }
                "state_dir" => {
                    // Deferred until we delete state_dir below.
                }
                _ => {}
            }
        }
        // D-15 WARNING-5: clear install_artifacts rows BEFORE we wipe the
        // state_dir (which contains the DB). Best-effort — the daemon may
        // have already torn down by now; if so the IPC fails gracefully.
        let _ = crate::ipc_client::delete_install_artifacts_request(
            sock,
            vec!["log_dir".into(), "state_dir".into()],
        );
        // Last: state_dir (which contains the DB we were just reading).
        let _ = std::fs::remove_dir_all(state_dir);
        Ok(())
    }
}
