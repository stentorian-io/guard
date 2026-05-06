//! crates/sentinel-daemon/src/log_writer/jsonl_row.rs
//!
//! Phase 3 plan 03-05 — JSONL row serde shapes (D-49). One JSON object per file line.

use serde::Serialize;
use sentinel_ipc::PackageContext;

pub const JSONL_SCHEMA_VERSION: u16 = 1;
pub const MAX_ARGV_BYTES: usize = 1024;

/// WR-12: cap on the number of argv elements logged per row. A malicious or
/// buggy package manager could spawn `tool arg1 arg2 ... argN` with N=100k,
/// producing JSONL rows that won't fit anywhere downstream. 256 is well
/// above any legitimate tool invocation (npm install + flags is < 50 args).
pub const MAX_ARGV_ELEMENTS: usize = 256;

#[derive(Serialize)]
#[serde(tag = "event")]
pub enum LogRow {
    #[serde(rename = "block")] Block(Decision),
    #[serde(rename = "allow")] Allow(Decision),
    #[serde(rename = "gap")] Gap(GapRecord),
}

#[derive(Serialize)]
pub struct Decision {
    pub schema_version: u16,
    pub ts: String,                                  // RFC3339 UTC w/ millis (Pitfall 9)
    pub verdict: &'static str,                       // "Allow" | "Deny"
    pub dest_host: String,
    pub dest_port: u16,
    pub dest_ip: Option<String>,
    pub run_uuid: String,
    pub source_kind: String,                         // Phase 2 D-27 enum string
    pub source_locator: Option<String>,
    pub process: ProcessCtxLog,
    pub parent: ProcessCtxLog,
    pub root: RootCtxLog,
    pub package_context: Option<PackageContext>,
    pub intel: Option<()>,                            // Phase 4 reserved (always None in Phase 3)
}

#[derive(Serialize)]
pub struct GapRecord {
    pub schema_version: u16,
    pub ts: String,
    pub run_uuid: String,
    pub gap_kind: &'static str,
    pub process: ProcessCtxLog,
    pub binary_path: Option<String>,
}

#[derive(Serialize, Clone)]
pub struct ProcessCtxLog {
    pub pid: u32,
    pub pidversion: u32,
    pub argv: Vec<String>,
    pub cwd: String,
}

#[derive(Serialize, Clone)]
pub struct RootCtxLog {
    pub audit_token: [u32; 8],
    pub argv: Vec<String>,
}

/// Per-element argv truncation per LOG schema (R-08 belt-and-braces, plus log-volume bound).
///
/// WR-12: also cap the total ELEMENT COUNT at MAX_ARGV_ELEMENTS. The previous
/// implementation only bounded each element's length, leaving the vector itself
/// unbounded — a buggy or hostile package manager spawning a tool with 100k
/// args would produce log rows that won't fit in the 64 KiB IPC frame limit
/// downstream. Append a synthetic placeholder telling the analyst how many
/// elements were dropped.
pub fn truncate_argv(mut argv: Vec<String>) -> Vec<String> {
    let original_len = argv.len();
    if original_len > MAX_ARGV_ELEMENTS {
        argv.truncate(MAX_ARGV_ELEMENTS - 1);
        argv.push(format!(
            "..(truncated, {} more args)",
            original_len - (MAX_ARGV_ELEMENTS - 1)
        ));
    }
    argv.into_iter().map(|s| truncate_str(s, MAX_ARGV_BYTES)).collect()
}

fn truncate_str(s: String, max: usize) -> String {
    if s.len() <= max { return s; }
    let mut end = max;
    while end > 0 && !s.is_char_boundary(end) { end -= 1; }
    s[..end].to_string()
}

/// Pitfall 9: explicit Millis precision + Z suffix → lexicographically-sortable.
pub fn now_rfc3339() -> String {
    chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
}

/// Append one row as a JSON line to the open writer. Preserves caller's file-open mode.
pub fn append(writer: &mut std::fs::File, row: &LogRow) -> std::io::Result<()> {
    use std::io::Write;
    serde_json::to_writer(&mut *writer, row)?;
    writer.write_all(b"\n")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ctx(pid: u32) -> ProcessCtxLog {
        ProcessCtxLog { pid, pidversion: 1, argv: vec!["node".into()], cwd: "/tmp".into() }
    }
    fn root() -> RootCtxLog {
        RootCtxLog { audit_token: [0; 8], argv: vec!["sentinel".into(), "run".into()] }
    }

    #[test]
    fn block_row_serializes_with_event_block() {
        let row = LogRow::Block(Decision {
            schema_version: JSONL_SCHEMA_VERSION,
            ts: "2026-05-08T17:42:01.234Z".into(),
            verdict: "Deny",
            dest_host: "evil.example.com".into(),
            dest_port: 443,
            dest_ip: None,
            run_uuid: "r1".into(),
            source_kind: "default_deny".into(),
            source_locator: None,
            process: ctx(1), parent: ctx(2), root: root(),
            package_context: None,
            intel: None,
        });
        let s = serde_json::to_string(&row).unwrap();
        assert!(s.starts_with("{\"event\":\"block\""), "got: {s}");
        assert!(s.contains("\"verdict\":\"Deny\""));
    }

    #[test]
    fn gap_row_serializes_with_event_gap() {
        let row = LogRow::Gap(GapRecord {
            schema_version: JSONL_SCHEMA_VERSION,
            ts: "2026-05-08T17:42:03.500Z".into(),
            run_uuid: "r1".into(),
            gap_kind: "hardened-runtime",
            process: ctx(3),
            binary_path: Some("/usr/bin/python3".into()),
        });
        let s = serde_json::to_string(&row).unwrap();
        assert!(s.starts_with("{\"event\":\"gap\""), "got: {s}");
        assert!(s.contains("\"gap_kind\":\"hardened-runtime\""));
    }

    #[test]
    fn now_rfc3339_lexicographic_ordering() {
        // Two close-in-time samples should still be lexicographically ordered.
        let t1 = now_rfc3339();
        std::thread::sleep(std::time::Duration::from_millis(2));
        let t2 = now_rfc3339();
        assert!(t1 <= t2, "RFC3339 strings not monotonically ordered: {t1} vs {t2}");
        assert!(t1.ends_with('Z'), "expect UTC Z suffix: {t1}");
    }

    #[test]
    fn truncate_argv_respects_max_bytes() {
        let arg = "a".repeat(MAX_ARGV_BYTES + 100);
        let out = truncate_argv(vec![arg]);
        assert_eq!(out.len(), 1);
        assert!(out[0].len() <= MAX_ARGV_BYTES);
    }
}
