//! crates/sentinel-cli/src/status/rules.rs
//!
//! Phase 07 plan 03 — `sentinel status rules [--all] [--project] [--json]`
//! (CLI-16, D-20). The CLI is a dumb client (D-21): it sends a `ListRules`
//! IPC request and formats the reply. The daemon owns rule storage and
//! filtering — the CLI never touches `sentinel.db` directly.
//!
//! Default scope: user + trusted_toml rules.
//! `--all`: include built-in registry-allowlist rules.
//! `--project`: walk `find_sentinel_toml(cwd)` and pass its canonical path
//!              as the daemon's project filter (Phase 2 D-36 boundary).
//! `--json`: emit the raw `Vec<RuleRow>` as JSON to stdout.

use std::path::Path;

use sentinel_ipc::RuleRow;

use crate::ipc_client;
use crate::CliError;

pub fn run(sock: &Path, all: bool, project: bool, json: bool) -> Result<i32, CliError> {
    let project_filter = if project {
        let cwd = std::env::current_dir()
            .map_err(|e| CliError::Other(format!("cwd: {e}")))?;
        match sentinel_core::policy_file::find_sentinel_toml(&cwd) {
            Some(toml_path) => {
                let canonical = toml_path
                    .canonicalize()
                    .map_err(|e| CliError::Other(format!(
                        "canonicalize {}: {e}",
                        toml_path.display()
                    )))?;
                Some(canonical.display().to_string())
            }
            None => {
                println!(
                    "sentinel: no .sentinel.toml found above {}",
                    cwd.display()
                );
                return Ok(0);
            }
        }
    } else {
        None
    };

    let rules = ipc_client::list_rules_request(sock, all, project_filter)?;

    if json {
        let s = serde_json::to_string(&rules)
            .map_err(|e| CliError::Other(format!("json: {e}")))?;
        println!("{s}");
        return Ok(0);
    }
    render_table(&rules);
    Ok(0)
}

fn render_table(rules: &[RuleRow]) {
    if rules.is_empty() {
        println!("(no rules)");
        return;
    }
    println!(
        "{:<14} {:<6} {:<8} {:<48} reason",
        "source", "kind", "match", "pattern"
    );
    let separator = "-".repeat(100);
    println!("{separator}");
    for r in rules {
        println!(
            "{:<14} {:<6} {:<8} {:<48} {}",
            r.source, r.kind, r.match_type, r.pattern, r.reason
        );
    }
}
