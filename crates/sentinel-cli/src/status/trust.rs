//! crates/sentinel-cli/src/status/trust.rs
//!
//! Phase 07 plan 03 — `sentinel status trust [--json]` (CLI-17, D-21).
//! Lists trusted .sentinel.toml entries by sending a `ListTrust` IPC
//! request to the daemon and formatting the reply.

use std::path::Path;

use sentinel_ipc::TrustRow;

use crate::ipc_client;
use crate::CliError;

pub fn run(sock: &Path, json: bool) -> Result<i32, CliError> {
    let mut entries = ipc_client::list_trust_request(sock)?;
    // Sort by trusted_at_ms ascending for stable display.
    entries.sort_by_key(|e| e.trusted_at_ms);

    if json {
        let s = serde_json::to_string(&entries)
            .map_err(|e| CliError::Other(format!("json: {e}")))?;
        println!("{s}");
        return Ok(0);
    }
    render_table(&entries);
    Ok(0)
}

fn render_table(entries: &[TrustRow]) {
    if entries.is_empty() {
        println!("(no trusted .sentinel.toml files)");
        return;
    }
    println!(
        "{:<60} {:<12} {:<24} {}",
        "path", "sha256", "trusted_at_ms", "via"
    );
    let separator = "-".repeat(110);
    println!("{separator}");
    for e in entries {
        let sha_short = if e.sha256.len() >= 12 {
            &e.sha256[..12]
        } else {
            &e.sha256
        };
        println!(
            "{:<60} {:<12} {:<24} {}",
            e.canonical_path, sha_short, e.trusted_at_ms, e.trusted_via
        );
    }
}
