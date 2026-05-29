//! crates/guard-cli/src/status/denials.rs
//!
//! `stt-guard status denials <run_uuid>`.
//! Reads the JSONL log directly via the `denial_log` parser (no IPC needed:
//! the log is the authoritative source for blocked-host events).

use crate::CliError;
use crate::denial_log;
use crate::install::launchagent;

/// Print denied destinations for a run.
///
/// # Errors
///
/// Returns an error when the forensic log cannot be read.
pub fn run(run_uuid: &str) -> Result<i32, CliError> {
    let log_path = launchagent::logs_dir().join(guard_core::paths::LOG_FILENAME);
    let blocks = denial_log::filter_block_destinations(&log_path, run_uuid)?;

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
