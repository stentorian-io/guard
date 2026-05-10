//! crates/sentinel-cli/src/install/mod.rs
//!
//! Phase 3 plan 03-09 — `sentinel install` orchestrator.
//!
//! Phase 07 plan 03 — factor the install body out of `run_install` so
//! the new `setup::apply_daemon` drift-repair path can re-apply on
//! Drifted state without going through the v0.1 TTY "Proceed?" confirm
//! and the no-package-managers-detected error gate. Idempotence
//! verified pre-task: `launchctl_bootstrap` is bootout-before-bootstrap
//! (Pitfall 6, `launchagent.rs:75-77`); `marker_block::install` uses
//! upsert; `init_script::install` is tempfile+atomic-rename;
//! `record_artifact` is INSERT OR REPLACE. The only non-idempotent
//! v0.1 surface (the unconditional TTY confirm and the pkg-mgr-required
//! error) is exactly what `apply_install_steps` deliberately omits.

pub mod artifacts;
pub mod drift;
pub mod init_script;
pub mod launchagent;
pub mod marker_block;
pub mod tui;
pub mod upgrade;

use std::path::{Path, PathBuf};

use crate::CliError;

const VERSION: &str = env!("CARGO_PKG_VERSION");

pub fn run_install(sock: &Path, state_dir: &Path, no_shell_integration: bool, reinstall: bool) -> Result<i32, CliError> {
    // Phase 07 D-13: when `reinstall == true`, wipe before re-installing.
    // run_remove handles its own confirmation (it uses tty::confirm which
    // refuses non-TTY stdin); we pass yes=true here because the caller
    // (install --reinstall) has already opted in to wiping.
    if reinstall {
        crate::uninstall::run_remove(sock, state_dir, /*target=*/ None, /*yes=*/ true)?;
    }

    let detected = tui::detect_package_managers();
    if !no_shell_integration && detected.is_empty() {
        return Err(CliError::Other(
            "no package managers detected on PATH; pass --no-shell-integration to skip dotfile mutation".into()
        ));
    }

    if std::io::IsTerminal::is_terminal(&std::io::stdin()) && !no_shell_integration {
        // MultiSelect (returns indices we keep — used purely as confirmation in v1; the marker block
        // is a generic stub that doesn't depend on per-tool aliases, so the picker is informational).
        let _ = tui::pick_aliases(&detected)?;
    }

    print_install_plan(state_dir, no_shell_integration);

    if std::io::IsTerminal::is_terminal(&std::io::stdin()) {
        if !confirm_yn("Proceed?")? {
            println!("Aborted.");
            return Ok(0);
        }
    }

    apply_install_steps(sock, state_dir, no_shell_integration)?;
    println!("Installed. Run `sentinel status` to verify.");
    Ok(0)
}

/// Phase 07 D-19: idempotent re-apply path for drift repair. Identical to
/// `run_install(.., no_shell_integration, reinstall=false)` minus the TTY
/// "Proceed?" confirm AND the no-package-managers-detected error gate.
/// Used by `setup::apply_daemon` / `setup::apply_shell` when they detect
/// `ComponentState::Drifted` or `Missing` and need to re-apply canonical
/// content without prompting the user.
pub fn run_install_unattended(
    sock: &Path,
    state_dir: &Path,
    no_shell_integration: bool,
) -> Result<i32, CliError> {
    apply_install_steps(sock, state_dir, no_shell_integration)
}

/// File-private helper: the actual idempotent install body. Both
/// `run_install` (interactive) and `run_install_unattended` (drift-repair)
/// call this. Each step is re-runnable without duplication; see the
/// idempotence rationale in the module-level doc comment above.
fn apply_install_steps(
    sock: &Path,
    state_dir: &Path,
    no_shell_integration: bool,
) -> Result<i32, CliError> {
    let _ = sock; // currently unused but kept for future IPC pre-checks
    let daemon_binary = resolve_daemon_binary()?;
    let plist = launchagent::plist_path();
    let log_dir = launchagent::logs_dir();
    let init_script = init_script::init_script_path();
    let db_path = state_dir.join("sentinel.db");
    let rc_files: Vec<PathBuf> = if no_shell_integration {
        Vec::new()
    } else {
        marker_block::detect_rc_files()
    };

    std::fs::create_dir_all(state_dir).ok();
    std::fs::create_dir_all(&log_dir).ok();

    // 1. plist
    let plist_value = launchagent::build_plist(&daemon_binary, state_dir);
    launchagent::write_plist(&plist, &plist_value)
        .map_err(|e| CliError::Other(format!("plist write: {e}")))?;
    artifacts::record_artifact(&db_path, "launchagent", &plist.display().to_string(), None, VERSION)?;

    // 2. init.sh
    let init_hash = init_script::install(&init_script).map_err(|e| CliError::Other(format!("init.sh: {e}")))?;
    artifacts::record_artifact(&db_path, "init_script", &init_script.display().to_string(), Some(&init_hash), VERSION)?;

    // 3. marker blocks
    for rc in &rc_files {
        let canonical = marker_block::install(rc).map_err(|e| CliError::Other(format!("marker {}: {e}", rc.display())))?;
        let hash = marker_block::canonical_block_sha256();
        artifacts::record_artifact(&db_path, "marker_block", &canonical.display().to_string(), Some(&hash), VERSION)?;
    }

    // 4. state_dir + log_dir tracking
    artifacts::record_artifact(&db_path, "state_dir", &state_dir.display().to_string(), None, VERSION)?;
    artifacts::record_artifact(&db_path, "log_dir", &log_dir.display().to_string(), None, VERSION)?;

    // 5. binary path (informational)
    artifacts::record_artifact(&db_path, "binary", &daemon_binary.display().to_string(), None, VERSION)?;

    // 5b. Hook dylib hash (M004-S03): write SHA-256 of libsentinel_hook.dylib
    //     to state_dir/hook.sha256 so the hook can self-verify at load time.
    if let Ok(dylib_path) = crate::locate::find_dylib() {
        if let Ok(hash) = compute_file_sha256(&dylib_path) {
            let hash_path = state_dir.join("hook.sha256");
            let _ = std::fs::write(&hash_path, format!("{hash}\n"));
            artifacts::record_artifact(&db_path, "hook_hash", &hash_path.display().to_string(), Some(&hash), VERSION)?;
        }
    }

    // 6. HMAC key (M004-S02): generate if not already present.
    let hmac_key_path = state_dir.join("hmac.key");
    if !hmac_key_path.exists() {
        sentinel_daemon::hmac_key::generate_and_store(state_dir)
            .map_err(|e| CliError::Other(format!("hmac key: {e}")))?;
    }
    artifacts::record_artifact(&db_path, "hmac_key", &hmac_key_path.display().to_string(), None, VERSION)?;

    // 7. launchctl bootstrap (Pitfall 6: bootout-before-bootstrap is
    //    handled inside this helper for idempotence).
    launchagent::launchctl_bootstrap(&plist).map_err(|e| CliError::Other(format!("bootstrap: {e}")))?;

    // 8. watchdog plist + bootstrap (M004-S01)
    if let Ok(watchdog_binary) = resolve_watchdog_binary() {
        let wd_plist_path = launchagent::watchdog_plist_path();
        let wd_plist_value = launchagent::build_watchdog_plist(&watchdog_binary, state_dir);
        launchagent::write_plist(&wd_plist_path, &wd_plist_value)
            .map_err(|e| CliError::Other(format!("watchdog plist write: {e}")))?;
        artifacts::record_artifact(
            &db_path,
            "launchagent_watchdog",
            &wd_plist_path.display().to_string(),
            None,
            VERSION,
        )?;
        artifacts::record_artifact(
            &db_path,
            "binary_watchdog",
            &watchdog_binary.display().to_string(),
            None,
            VERSION,
        )?;
        launchagent::launchctl_bootstrap_watchdog(&wd_plist_path)
            .map_err(|e| CliError::Other(format!("watchdog bootstrap: {e}")))?;
    }

    Ok(0)
}

/// Print the v0.1-shape "sentinel install plan: ..." block. Only called
/// from interactive `run_install`. `run_install_unattended` (drift repair)
/// uses `setup::apply_*`'s "sentinel: repaired/installed <path>" line per
/// D-19, so this is intentionally not called from the unattended path.
fn print_install_plan(state_dir: &Path, no_shell_integration: bool) {
    let plist = launchagent::plist_path();
    let log_dir = launchagent::logs_dir();
    let init_script = init_script::init_script_path();
    let rc_files: Vec<PathBuf> = if no_shell_integration {
        Vec::new()
    } else {
        marker_block::detect_rc_files()
    };
    println!("sentinel install plan:");
    if let Ok(daemon_binary) = resolve_daemon_binary() {
        println!("  daemon:    {}", daemon_binary.display());
    }
    println!("  plist:     {}", plist.display());
    println!("  log dir:   {}", log_dir.display());
    println!("  state dir: {}", state_dir.display());
    println!("  init.sh:   {}", init_script.display());
    if no_shell_integration {
        println!("  rc files:  (none — --no-shell-integration)");
    } else {
        for rc in &rc_files {
            println!("  rc file:   {}", rc.display());
        }
    }
}

/// Phase 07 plan 02: promoted to `pub(crate)` so `install::drift` can resolve
/// the daemon binary path when reconstructing the canonical plist for content
/// comparison.
pub(crate) fn resolve_daemon_binary() -> Result<PathBuf, CliError> {
    if let Some(path) = std::env::var_os("SENTINEL_DAEMON_BINARY") {
        return Ok(PathBuf::from(path));
    }
    let path_var = std::env::var_os("PATH").ok_or_else(|| CliError::Other("PATH not set".into()))?;
    for dir in std::env::split_paths(&path_var) {
        let cand = dir.join("sentineld");
        if cand.is_file() { return Ok(cand); }
    }
    Err(CliError::Other("sentineld not found on PATH; install via brew or set SENTINEL_DAEMON_BINARY".into()))
}

pub(crate) fn resolve_watchdog_binary() -> Result<PathBuf, CliError> {
    if let Some(path) = std::env::var_os("SENTINEL_WATCHDOG_BINARY") {
        return Ok(PathBuf::from(path));
    }
    let path_var = std::env::var_os("PATH").ok_or_else(|| CliError::Other("PATH not set".into()))?;
    for dir in std::env::split_paths(&path_var) {
        let cand = dir.join("sentinel-watchdog");
        if cand.is_file() { return Ok(cand); }
    }
    // Watchdog is optional — fall back to sibling of daemon binary
    if let Ok(daemon) = resolve_daemon_binary() {
        if let Some(dir) = daemon.parent() {
            let cand = dir.join("sentinel-watchdog");
            if cand.is_file() {
                return Ok(cand);
            }
        }
    }
    Err(CliError::Other("sentinel-watchdog not found on PATH; set SENTINEL_WATCHDOG_BINARY".into()))
}

fn compute_file_sha256(path: &Path) -> std::io::Result<String> {
    use sha2::{Digest, Sha256};
    let bytes = std::fs::read(path)?;
    Ok(format!("{:x}", Sha256::digest(&bytes)))
}

fn confirm_yn(prompt: &str) -> Result<bool, CliError> {
    // WR-04: reject non-TTY stdin so piped input (`yes |`, `< answers.txt`)
    // can never silently agree to install. Callers that genuinely need to
    // skip interactive confirmation should branch on their own
    // is_terminal()/--yes flag and never call this helper from a non-TTY
    // path.
    use std::io::{BufRead, IsTerminal, Write};
    if !std::io::stdin().is_terminal() {
        return Err(CliError::Other(format!(
            "{prompt} (TTY required for confirmation; re-run interactively)"
        )));
    }
    print!("{prompt} [y/N] ");
    std::io::stdout().flush().map_err(|e| CliError::Other(format!("stdout: {e}")))?;
    let mut line = String::new();
    std::io::stdin().lock().read_line(&mut line).map_err(|e| CliError::Other(format!("stdin: {e}")))?;
    Ok(matches!(line.trim().to_lowercase().as_str(), "y" | "yes"))
}
