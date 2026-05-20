//! crates/sentinel-cli/src/status/rules.rs
//!
//! `sentinel status rules [--include-built-in] [--disable <pattern> --reason <reason>] [--enable <pattern>]`.

use std::path::Path;

use sentinel_ipc::RuleRow;

use crate::ipc_client;
use crate::CliError;

pub fn run(
    sock: &Path,
    include_built_in: bool,
    disable: Option<String>,
    enable: Option<String>,
    reason: Option<String>,
) -> Result<i32, CliError> {
    if let Some(pattern) = disable {
        let reason = match reason {
            Some(r) if !r.trim().is_empty() => r,
            _ => {
                eprintln!("sentinel: --disable requires --reason");
                return Ok(64); // EX_USAGE
            }
        };
        ipc_client::disable_curated_rule_request(sock, &pattern, &reason)?;
        eprintln!("Disabled built-in rule: {pattern}");
        return Ok(0);
    }

    if let Some(pattern) = enable {
        let was_disabled = ipc_client::enable_curated_rule_request(sock, &pattern)?;
        if was_disabled {
            eprintln!("Re-enabled built-in rule: {pattern}");
        } else {
            eprintln!("Rule was not disabled: {pattern}");
        }
        return Ok(0);
    }

    let rules = ipc_client::list_rules_request(sock, include_built_in)?;
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
