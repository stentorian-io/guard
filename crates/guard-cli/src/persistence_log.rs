//! JSONL log parser for persistence-write gap events (M003-S05).
//!
//! Mirrors `denial_log.rs` but filters for `event=gap, gap_kind=persistence-write`.

use std::io::{BufRead, BufReader};
use std::path::Path;

use crate::CliError;

pub const MAX_ENTRIES: usize = 10_000;

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PersistenceEntry {
    pub ts: String,
    pub run_uuid: String,
    pub binary_path: String,
    pub pid: Option<u64>,
}

/// Walk the JSONL log filtering persistence-write gap events.
///
/// # Errors
///
/// Returns an error when the log exists but cannot be opened.
pub fn filter_persistence_writes(
    log_path: &Path,
    run_uuid: Option<&str>,
) -> Result<Vec<PersistenceEntry>, CliError> {
    let file = match std::fs::File::open(log_path) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(CliError::Other(format!("open log: {e}"))),
    };
    let reader = BufReader::new(file);
    let mut out = Vec::new();
    for line in reader.lines() {
        let Ok(line) = line else {
            continue;
        };
        if line.trim().is_empty() {
            continue;
        }
        let v: serde_json::Value = match serde_json::from_str(&line) {
            Ok(v) => v,
            Err(_) => continue,
        };
        if v.get("event").and_then(|e| e.as_str()) != Some("gap") {
            continue;
        }
        if v.get("gap_kind").and_then(|g| g.as_str()) != Some("persistence-write") {
            continue;
        }
        if let Some(uuid_filter) = run_uuid {
            if v.get("run_uuid").and_then(|r| r.as_str()) != Some(uuid_filter) {
                continue;
            }
        }
        let ts = v
            .get("ts")
            .and_then(|t| t.as_str())
            .unwrap_or("")
            .to_string();
        let ruuid = v
            .get("run_uuid")
            .and_then(|r| r.as_str())
            .unwrap_or("")
            .to_string();
        let binary_path = v
            .get("binary_path")
            .and_then(|b| b.as_str())
            .unwrap_or("")
            .to_string();
        let pid = v
            .get("process")
            .and_then(|p| p.get("pid"))
            .and_then(serde_json::Value::as_u64);

        if binary_path.is_empty() {
            continue;
        }
        out.push(PersistenceEntry {
            ts,
            run_uuid: ruuid,
            binary_path,
            pid,
        });
        if out.len() >= MAX_ENTRIES {
            break;
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn returns_empty_for_missing_log() {
        let dir = tempdir().unwrap();
        let log = dir.path().join("absent.log");
        let result = filter_persistence_writes(&log, None).unwrap();
        assert!(result.is_empty());
    }

    #[test]
    fn filters_persistence_write_gaps() {
        let dir = tempdir().unwrap();
        let log = dir.path().join("test.log");
        let lines = [
            r#"{"event":"gap","gap_kind":"persistence-write","ts":"2026-05-10T12:00:00.000Z","run_uuid":"R1","binary_path":"/Users/x/Library/LaunchAgents/evil.plist","process":{"pid":123,"pidversion":1,"argv":[],"cwd":""}}"#,
            r#"{"event":"gap","gap_kind":"hardened-runtime","ts":"2026-05-10T12:00:01.000Z","run_uuid":"R1","binary_path":"/usr/bin/curl","process":{"pid":124,"pidversion":1,"argv":[],"cwd":""}}"#,
            r#"{"event":"block","run_uuid":"R1","dest_host":"evil.com","dest_port":443}"#,
            r#"{"event":"gap","gap_kind":"persistence-write","ts":"2026-05-10T12:00:02.000Z","run_uuid":"R2","binary_path":"/Library/LaunchDaemons/bad.plist","process":{"pid":125,"pidversion":1,"argv":[],"cwd":""}}"#,
        ];
        std::fs::write(&log, lines.join("\n")).unwrap();

        let all = filter_persistence_writes(&log, None).unwrap();
        assert_eq!(all.len(), 2);
        assert_eq!(
            all[0].binary_path,
            "/Users/x/Library/LaunchAgents/evil.plist"
        );
        assert_eq!(all[1].binary_path, "/Library/LaunchDaemons/bad.plist");

        let r1_only = filter_persistence_writes(&log, Some("R1")).unwrap();
        assert_eq!(r1_only.len(), 1);
        assert_eq!(r1_only[0].run_uuid, "R1");
    }

    #[test]
    fn extracts_pid_from_process() {
        let dir = tempdir().unwrap();
        let log = dir.path().join("pid.log");
        let line = r#"{"event":"gap","gap_kind":"persistence-write","ts":"T","run_uuid":"R","binary_path":"/tmp/evil","process":{"pid":42,"pidversion":1,"argv":[],"cwd":""}}"#;
        std::fs::write(&log, line).unwrap();
        let entries = filter_persistence_writes(&log, None).unwrap();
        assert_eq!(entries[0].pid, Some(42));
    }
}
