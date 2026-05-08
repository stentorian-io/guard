//! crates/sentinel-cli/src/status/denials.rs
//!
//! Phase 07 plan 03 — `sentinel status denials <run_uuid> [--json]`
//! (CLI-18, D-22). Reads the JSONL log directly via the `denial_log`
//! parser (no IPC needed: the log is the authoritative source for
//! blocked-host events per D-22).

use crate::denial_log;
use crate::install::launchagent;
use crate::CliError;

pub fn run(run_uuid: &str, json: bool) -> Result<i32, CliError> {
    let log_path = launchagent::logs_dir().join("sentinel.log");
    let blocks = denial_log::filter_block_destinations(&log_path, run_uuid)?;

    if json {
        let s = serde_json::to_string(&blocks)
            .map_err(|e| CliError::Other(format!("json: {e}")))?;
        println!("{s}");
        return Ok(0);
    }
    if blocks.is_empty() {
        println!("No block entries found for run_uuid={run_uuid}.");
        return Ok(0);
    }
    for b in &blocks {
        println!(
            "  {} (port {})  source_kind={}",
            b.host, b.port, b.source_kind
        );
    }
    Ok(0)
}
