//! crates/sentinel-cli/src/install/mod.rs
//!
//! Phase 3 plan 03-09 — `sentinel install` orchestrator.

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

pub fn run_install(
    _sock: &Path,
    state_dir: &Path,
    no_shell_integration: bool,
    _reinstall: bool,
) -> Result<i32, CliError> {
    let daemon_binary = resolve_daemon_binary()?;
    let plist = launchagent::plist_path();
    let log_dir = launchagent::logs_dir();
    let init_script = init_script::init_script_path();
    let db_path = state_dir.join("sentinel.db");

    let detected = tui::detect_package_managers();
    let rc_files: Vec<PathBuf> = if no_shell_integration { Vec::new() } else { marker_block::detect_rc_files() };

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

    println!("sentinel install plan:");
    println!("  daemon:    {}", daemon_binary.display());
    println!("  plist:     {}", plist.display());
    println!("  log dir:   {}", log_dir.display());
    println!("  state dir: {}", state_dir.display());
    println!("  init.sh:   {}", init_script.display());
    if no_shell_integration {
        println!("  rc files:  (none — --no-shell-integration)");
    } else {
        for rc in &rc_files { println!("  rc file:   {}", rc.display()); }
    }
    if std::io::IsTerminal::is_terminal(&std::io::stdin()) {
        if !confirm_yn("Proceed?")? {
            println!("Aborted.");
            return Ok(0);
        }
    }

    // Apply.
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

    // 6. launchctl bootstrap
    launchagent::launchctl_bootstrap(&plist).map_err(|e| CliError::Other(format!("bootstrap: {e}")))?;

    println!("Installed. Run `sentinel status` to verify.");
    Ok(0)
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
