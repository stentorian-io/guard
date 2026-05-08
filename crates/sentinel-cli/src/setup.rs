//! crates/sentinel-cli/src/setup.rs
//!
//! Phase 07 plan 03 — `sentinel setup [target] [--remove|--reinstall] [-y]`
//! dispatch (CLI-11..CLI-13). Composition over `install::run_install`,
//! `uninstall::run_remove`, and `install::drift::detect_*`.
//!
//! Behaviour summary:
//!   - bare `setup`        → drift-safe idempotent re-apply (D-19)
//!   - `setup --remove`    → forwards to `uninstall::run_remove`
//!   - `setup --reinstall` → confirm (D-17 destruction message) → wipe →
//!                            re-apply
//!   - `--remove` and `--reinstall` are mutually exclusive (RESEARCH.md
//!     Open Question #1, option a — clap's `conflicts_with` is the
//!     primary line of defense; this is belt-and-suspenders).

use std::path::Path;

use crate::install::{self, drift, launchagent};
use crate::uninstall::{run_remove, SetupTarget};
use crate::{shell_setup, tty, CliError};

/// Top-level setup dispatcher. Mutually exclusive: --remove and --reinstall
/// (RESEARCH.md Open Question #1, option a).
pub fn run_setup(
    sock: &Path,
    state_dir: &Path,
    target: Option<SetupTarget>,
    remove: bool,
    reinstall: bool,
    yes: bool,
) -> Result<i32, CliError> {
    if remove && reinstall {
        return Err(CliError::Other(
            "--remove and --reinstall are mutually exclusive".into(),
        ));
    }
    if remove {
        return run_remove(sock, state_dir, target, yes);
    }
    if reinstall {
        return run_reinstall(sock, state_dir, target, yes);
    }
    // Bare `setup` — drift-safe idempotent re-apply (D-19).
    run_apply(sock, state_dir, target)
}

/// D-16/D-17: force-clean wipe + re-derive. Confirmation prompt MUST
/// spell out destruction (RESEARCH.md Open Question #2 wording).
fn run_reinstall(
    sock: &Path,
    state_dir: &Path,
    target: Option<SetupTarget>,
    yes: bool,
) -> Result<i32, CliError> {
    if !yes {
        let log_dir = launchagent::logs_dir();
        let prompt = match target {
            None => format!(
                "This will delete all rules, trust entries, logs, and shell aliases \
                 under {} and {}, then reinstall from scratch. Continue?",
                state_dir.display(),
                log_dir.display(),
            ),
            Some(SetupTarget::Daemon) => format!(
                "This will remove the daemon LaunchAgent and plist (preserving rules, \
                 logs, and shell aliases) under {}, then reinstall the daemon. Continue?",
                state_dir.display(),
            ),
            Some(SetupTarget::Shell) => {
                "This will remove the Sentinel shell marker blocks (preserving daemon, \
                 rules, and logs), then reinstall the shell aliases. Continue?"
                    .to_string()
            }
        };
        if !tty::confirm(&prompt)? {
            println!("Aborted.");
            return Ok(0);
        }
    }
    // RESEARCH.md A7: simple sequencing. run_remove already does the bootout
    // 250ms sleep before state-dir delete (Pitfall 5).
    run_remove(sock, state_dir, target, /*yes=*/ true)?;
    run_apply(sock, state_dir, target)
}

/// D-19: terraform-style apply against converged infra. Each component
/// produces one of three messages: "already installed at ..." (Converged),
/// "repaired ..." (Drifted, re-apply), "installed ..." (Missing, apply).
fn run_apply(
    sock: &Path,
    state_dir: &Path,
    target: Option<SetupTarget>,
) -> Result<i32, CliError> {
    let do_daemon = matches!(target, None | Some(SetupTarget::Daemon));
    let do_shell = matches!(target, None | Some(SetupTarget::Shell));

    if do_daemon {
        apply_daemon(sock, state_dir)?;
    }
    if do_shell {
        apply_shell(state_dir)?;
    }
    Ok(0)
}

fn apply_daemon(sock: &Path, state_dir: &Path) -> Result<(), CliError> {
    // `drift::detect_launchagent` requires `(daemon_binary, state_dir)` to
    // reconstruct the canonical plist for parsed-Value comparison. If the
    // daemon binary cannot be resolved (e.g. brew has not yet placed
    // `sentineld` on PATH), treat as Missing and let the install body's
    // `resolve_daemon_binary` produce the canonical error message.
    let state = match install::resolve_daemon_binary() {
        Ok(daemon_binary) => drift::detect_launchagent(&daemon_binary, state_dir),
        Err(_) => drift::ComponentState::Missing,
    };
    match state {
        drift::ComponentState::Converged => {
            println!(
                "sentinel: already installed at {} (daemon)",
                launchagent::plist_path().display()
            );
        }
        drift::ComponentState::Drifted { reason } => {
            println!("sentinel: daemon drift detected ({reason}); repairing");
            // Drift repair: use the unattended path (skips the v0.1 "Proceed?"
            // confirm + pkg-mgr-required gate; calls into the same idempotent
            // install body — see install module's run_install_unattended).
            install::run_install_unattended(sock, state_dir, /*no_shell_integration=*/ true)?;
            println!(
                "sentinel: repaired {} (daemon)",
                launchagent::plist_path().display()
            );
        }
        drift::ComponentState::Missing => {
            install::run_install_unattended(sock, state_dir, /*no_shell_integration=*/ true)?;
            println!(
                "sentinel: installed {} (daemon)",
                launchagent::plist_path().display()
            );
        }
    }
    Ok(())
}

fn apply_shell(state_dir: &Path) -> Result<(), CliError> {
    let states = drift::detect_marker_blocks();
    let init_state = drift::detect_init_script();

    // If everything is converged, one summary line.
    if states
        .iter()
        .all(|(_, s)| matches!(s, drift::ComponentState::Converged))
        && matches!(init_state, drift::ComponentState::Converged)
    {
        println!("sentinel: shell aliases already installed");
        return Ok(());
    }
    // Otherwise re-apply via shell_setup (idempotent: it skips rc files
    // that already contain the canonical block, and overwrites those that
    // don't via marker_block::install).
    shell_setup::run_shell_setup(state_dir)?;
    for (rc, st) in &states {
        match st {
            drift::ComponentState::Converged => {}
            drift::ComponentState::Drifted { .. } => {
                println!("sentinel: repaired marker block in {}", rc.display());
            }
            drift::ComponentState::Missing => {
                println!("sentinel: installed marker block in {}", rc.display());
            }
        }
    }
    match init_state {
        drift::ComponentState::Converged => {}
        drift::ComponentState::Drifted { .. } => {
            println!("sentinel: repaired init script");
        }
        drift::ComponentState::Missing => {
            println!("sentinel: installed init script");
        }
    }
    Ok(())
}
