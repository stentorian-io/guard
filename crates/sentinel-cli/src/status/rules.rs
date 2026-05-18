//! crates/sentinel-cli/src/status/rules.rs
//!
//! `sentinel status rules [--all] [--json]` (CLI-16).

use std::path::Path;

use sentinel_ipc::RuleRow;

use crate::ipc_client;
use crate::CliError;

pub fn run(sock: &Path, all: bool, json: bool) -> Result<i32, CliError> {
    let rules = ipc_client::list_rules_request(sock, all)?;

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
