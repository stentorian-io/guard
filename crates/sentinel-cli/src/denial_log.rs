//! crates/sentinel-cli/src/denial_log.rs
//!
//! Phase 07 plan 02 — JSONL denial-log parser, refactored from approve.rs
//! per D-22. Consumed by `status denials <uuid>` and `status review [<uuid>]`
//! (Plan 03). WR-05 caps preserved verbatim (D-30): max 10 000 unique
//! hosts, max 256-char host length.

use std::io::{BufRead, BufReader};
use std::path::Path;

use crate::CliError;

/// WR-05: cap the unique-host count we accumulate when filtering block
/// destinations. Without a cap, a hostile package making thousands of
/// unique hostnames per run could OOM the CLI.
pub const MAX_UNIQUE_BLOCK_HOSTS: usize = 10_000;

/// WR-05: cap the per-host hostname length we accept.
pub const MAX_HOST_LENGTH: usize = 256;

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct BlockEntry {
    pub host: String,
    pub port: u16,
    pub source_kind: String,
}

/// Walk the JSONL log filtering `block` events for a specific run_uuid.
/// Returns deduplicated (host, port) pairs in insertion order.
/// Errors: file-not-found, > MAX_UNIQUE_BLOCK_HOSTS unique hosts.
pub fn filter_block_destinations(log_path: &Path, run_uuid: &str)
    -> Result<Vec<BlockEntry>, CliError>
{
    let file = match std::fs::File::open(log_path) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Err(CliError::Other(format!("log file missing: {}", log_path.display())));
        }
        Err(e) => return Err(CliError::Other(format!("open log: {e}"))),
    };
    let reader = BufReader::new(file);
    let mut seen: std::collections::HashSet<(String, u16)> = std::collections::HashSet::new();
    let mut out = Vec::new();
    for line in reader.lines() {
        let line = match line { Ok(l) => l, Err(_) => continue };
        if line.trim().is_empty() { continue; }
        let v: serde_json::Value = match serde_json::from_str(&line) { Ok(v) => v, Err(_) => continue };
        if v.get("event").and_then(|e| e.as_str()) != Some("block") { continue; }
        if v.get("run_uuid").and_then(|r| r.as_str()) != Some(run_uuid) { continue; }
        let host = v.get("dest_host").and_then(|h| h.as_str()).unwrap_or("");
        let port = v.get("dest_port").and_then(|p| p.as_u64()).unwrap_or(0) as u16;
        let source_kind = v.get("source_kind").and_then(|s| s.as_str()).unwrap_or("").to_string();
        if host.is_empty() { continue; }
        if host.len() > MAX_HOST_LENGTH { continue; }
        if seen.insert((host.to_string(), port)) {
            out.push(BlockEntry { host: host.to_string(), port, source_kind });
            if out.len() >= MAX_UNIQUE_BLOCK_HOSTS {
                return Err(CliError::Other(format!(
                    "log contains > {MAX_UNIQUE_BLOCK_HOSTS} unique blocked hosts for run {run_uuid}; \
                     refusing to load — re-run after rotating the log"
                )));
            }
        }
    }
    Ok(out)
}

/// D-26: walk the log and return the run_uuid of the most recent line
/// whose event == "block". Returns None if no block events exist.
/// Implementation: read the file once, accumulate the LAST seen block
/// run_uuid (later lines overwrite earlier ones). v1 reads the whole
/// file; MAX_UNIQUE_BLOCK_HOSTS already bounds memory pressure.
///
/// File-not-found is treated as "no denials yet" (returns Ok(None))
/// rather than an error — the consumer (`status review`) interprets
/// this as a benign "fresh install / nothing to review" condition.
pub fn most_recent_run_with_denials(log_path: &Path) -> Result<Option<String>, CliError> {
    let file = match std::fs::File::open(log_path) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(CliError::Other(format!("open log: {e}"))),
    };
    let reader = BufReader::new(file);
    let mut latest: Option<String> = None;
    for line in reader.lines() {
        let line = match line { Ok(l) => l, Err(_) => continue };
        if line.trim().is_empty() { continue; }
        let v: serde_json::Value = match serde_json::from_str(&line) { Ok(v) => v, Err(_) => continue };
        if v.get("event").and_then(|e| e.as_str()) != Some("block") { continue; }
        if let Some(uuid) = v.get("run_uuid").and_then(|r| r.as_str()) {
            latest = Some(uuid.to_string());
        }
    }
    Ok(latest)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn most_recent_returns_none_for_empty_log() {
        let dir = tempdir().unwrap();
        let log = dir.path().join("empty.log");
        std::fs::write(&log, "").unwrap();
        assert!(most_recent_run_with_denials(&log).unwrap().is_none());
    }

    #[test]
    fn most_recent_returns_none_for_missing_log() {
        let dir = tempdir().unwrap();
        let log = dir.path().join("absent.log");
        // File-not-found is benign: no denials yet.
        assert!(most_recent_run_with_denials(&log).unwrap().is_none());
    }

    #[test]
    fn most_recent_returns_last_block_uuid() {
        let dir = tempdir().unwrap();
        let log = dir.path().join("multi.log");
        let lines = [
            r#"{"event":"block","run_uuid":"X","dest_host":"a"}"#,
            r#"{"event":"allow","run_uuid":"Y","dest_host":"b"}"#,
            r#"{"event":"block","run_uuid":"Z","dest_host":"c"}"#,
            r#"{"event":"gap","run_uuid":"W"}"#,
        ];
        std::fs::write(&log, lines.join("\n")).unwrap();
        assert_eq!(most_recent_run_with_denials(&log).unwrap(), Some("Z".into()));
    }

    #[test]
    fn most_recent_skips_non_block_events() {
        let dir = tempdir().unwrap();
        let log = dir.path().join("only_allows.log");
        let lines = [
            r#"{"event":"allow","run_uuid":"A","dest_host":"a"}"#,
            r#"{"event":"gap","run_uuid":"B"}"#,
        ];
        std::fs::write(&log, lines.join("\n")).unwrap();
        assert!(most_recent_run_with_denials(&log).unwrap().is_none());
    }
}
