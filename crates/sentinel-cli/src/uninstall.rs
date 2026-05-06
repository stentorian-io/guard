//! crates/sentinel-cli/src/uninstall.rs

use std::io::IsTerminal;
use std::path::Path;

use crate::install::{artifacts, init_script, launchagent, marker_block};
use crate::CliError;

pub fn run_uninstall(sock: &Path, state_dir: &Path, force: bool) -> Result<i32, CliError> {
    if !force {
        if !std::io::stdin().is_terminal() {
            return Err(CliError::Other(
                "uninstall requires a TTY for y/N confirmation; use --force to skip".into()
            ));
        }
        if !confirm("This will remove the daemon, all rules, all logs, all trust entries, and all shell aliases. Continue?")? {
            println!("Aborted.");
            return Ok(0);
        }
    }
    let db_path = state_dir.join("sentinel.db");
    let artifacts_list = artifacts::read_artifacts(sock, &db_path).unwrap_or_default();

    // 1. launchctl bootout (Pitfall 6: ignore non-zero).
    let _ = launchagent::launchctl_bootout();
    std::thread::sleep(std::time::Duration::from_millis(250));

    // 2. Reverse artifacts in D-64 order.
    for art in &artifacts_list {
        match art.artifact_kind.as_str() {
            "marker_block" => { let _ = marker_block::strip(Path::new(&art.target_path)); }
            "init_script"  => { let _ = init_script::strip(Path::new(&art.target_path)); }
            "launchagent"  => { let _ = std::fs::remove_file(&art.target_path); }
            "state_dir"    => { /* deferred until we delete db ourselves below */ }
            "log_dir"      => { let _ = std::fs::remove_dir_all(&art.target_path); }
            "binary"       => { /* D-65: brew owns, skip */ }
            _ => {}
        }
    }
    // 3. Last: state_dir (which contains the DB we were just reading from).
    let _ = std::fs::remove_dir_all(state_dir);
    println!("Uninstalled. (`brew uninstall sentinel` removes the binary.)");
    Ok(0)
}

fn confirm(prompt: &str) -> Result<bool, CliError> {
    use std::io::{BufRead, Write};
    print!("{prompt} [y/N] ");
    std::io::stdout().flush().map_err(|e| CliError::Other(format!("stdout: {e}")))?;
    let mut line = String::new();
    std::io::stdin().lock().read_line(&mut line).map_err(|e| CliError::Other(format!("stdin: {e}")))?;
    Ok(matches!(line.trim().to_lowercase().as_str(), "y" | "yes"))
}
