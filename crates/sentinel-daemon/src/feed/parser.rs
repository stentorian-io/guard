//! v0.4 — OSV record parser + host-IoC extractor.
//!
//! Inputs: raw JSON bytes from a single OSV file (typically <8 KB; capped at
//! `MAX_OSV_RECORD_BYTES` = 64 KB per RESEARCH.md Security V5).
//!
//! Outputs: a `ParsedRecord` with the fields needed to build `feed_iocs`
//! rows, OR a `FeedParseError` that the fetcher counts as parse_error /
//! schema_unknown / oversized for last-good-cache + feed_warning surfacing.
//!
//! Schema-version range gate (TI-06 per PATTERNS.md correction #6):
//!   - GHSA records ship `schema_version: "1.4.0"` (haven't migrated since 2023).
//!   - MAL records ship `schema_version: "1.7.4"` (or current).
//!   - Accept range `>= 1.4.0, < 2.0.0` — OSV is committed to backward-compat
//!     within major-version 1.x.
//!   - Out-of-range records raise `FeedParseError::SchemaUnknown` (loud).
//!
//! Host extraction (per 04-SPIKE-RESULTS.md A4 + RESEARCH.md Pitfall 4):
//!   - PRIMARY signal: `database_specific.iocs.{domains,ips}` (default-included
//!     in v1; `iocs.urls[]` is intentionally EXCLUDED due to over-block risk
//!     for legitimate hosts like discord.com / cdn.discordapp.com / dl.dropbox.com).
//!   - SECONDARY signal: `references[].type IN ('EVIDENCE', 'REPORT')` →
//!     parse URL host via `url::Url::host_str()`.
//!   - The speculative names (`malicious_hosts`, `c2`,
//!     `exfil_hosts`) DO NOT exist in real data — explicitly NOT looked up.

use serde_json::Value;

pub const MAX_OSV_RECORD_BYTES: usize = 64 * 1024;
pub const MAX_HOST_IOC_LEN: usize = 256;
pub const MAX_ADVISORY_ID_LEN: usize = 64;
pub const MAX_TAG_BYTES: usize = 64;

/// Inclusive lower bound on accepted OSV `schema_version`. (Major, minor) tuple.
const SCHEMA_VERSION_MIN: (u32, u32) = (1, 4);
/// Exclusive upper bound on accepted OSV `schema_version`. (Major, minor) tuple.
const SCHEMA_VERSION_MAX_EXCLUSIVE: (u32, u32) = (2, 0);

#[derive(Debug, thiserror::Error)]
pub enum FeedParseError {
    #[error("oversized record: {bytes} bytes (cap {cap})")]
    OversizedRecord { bytes: usize, cap: usize },
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
    #[error(
        "schema_version unknown: observed={observed:?}, expected range >=1.4.0,<2.0.0"
    )]
    SchemaUnknown { observed: Option<String> },
    #[error("advisory_id invalid: {reason}")]
    InvalidAdvisoryId { reason: String },
    #[error("missing required field: {field}")]
    MissingField { field: &'static str },
}

/// Parsed `affected[]` element — one row per affected{ecosystem,package}
/// produces a `feed_iocs` row when the fetcher writes to the store.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AffectedBlock {
    pub ecosystem: String,
    pub package: String,
    /// Serialized JSON subset `{ "versions": [...], "ranges": [...] }` — the
    /// shape `osv_match::version_in_affected_block` consumes at log-write
    /// enrichment time. Stored as TEXT in the `feed_iocs.versions_json` column.
    pub versions_json: String,
}

#[derive(Debug, Clone)]
pub struct ParsedRecord {
    pub advisory_id: String,
    pub schema_version_observed: String,
    pub published_ms: i64,
    pub severity: Option<String>,
    pub tag: Option<String>,
    pub affected: Vec<AffectedBlock>,
    pub host_iocs: Vec<String>,
    /// Retained so the fetcher can store the original JSON body in
    /// `feed_iocs.versions_json` if the affected block list is empty (for
    /// host-only IoC rows).
    pub raw: Value,
}

/// Parse a single OSV record. The byte length is capped before
/// `serde_json::from_slice` so the runtime allocator doesn't see an
/// adversarial 1 MB string masquerading as JSON.
pub fn parse_osv_record(json: &[u8], _feed: &str) -> Result<ParsedRecord, FeedParseError> {
    if json.len() > MAX_OSV_RECORD_BYTES {
        return Err(FeedParseError::OversizedRecord {
            bytes: json.len(),
            cap: MAX_OSV_RECORD_BYTES,
        });
    }

    let v: Value = serde_json::from_slice(json)?;

    // Schema-version range gate (TI-06).
    let observed = v
        .get("schema_version")
        .and_then(|s| s.as_str())
        .map(String::from);
    let pair = observed.as_deref().and_then(parse_semver_pair);
    match pair {
        Some(p) if p >= SCHEMA_VERSION_MIN && p < SCHEMA_VERSION_MAX_EXCLUSIVE => {}
        _ => return Err(FeedParseError::SchemaUnknown { observed }),
    }
    let schema_version_observed = observed.expect("present after gate");

    // Advisory ID (required, capped).
    let advisory_id = v
        .get("id")
        .and_then(|s| s.as_str())
        .ok_or(FeedParseError::MissingField { field: "id" })?
        .to_string();
    if advisory_id.is_empty() {
        return Err(FeedParseError::InvalidAdvisoryId {
            reason: "empty".into(),
        });
    }
    if advisory_id.len() > MAX_ADVISORY_ID_LEN {
        return Err(FeedParseError::InvalidAdvisoryId {
            reason: format!(
                "exceeds {MAX_ADVISORY_ID_LEN} bytes (got {})",
                advisory_id.len()
            ),
        });
    }

    // published → unix-ms (default 0 if missing/unparseable).
    let published_ms = v
        .get("published")
        .and_then(|s| s.as_str())
        .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
        .map(|dt| dt.timestamp_millis())
        .unwrap_or(0);

    // Severity: first severity[].score string, if any.
    let severity = v
        .get("severity")
        .and_then(|arr| arr.as_array())
        .and_then(|arr| arr.first())
        .and_then(|first| first.get("score"))
        .and_then(|s| s.as_str())
        .map(String::from);

    // Tag from summary, truncated to MAX_TAG_BYTES (utf-8-safe).
    let tag = v
        .get("summary")
        .and_then(|s| s.as_str())
        .map(|s| truncate_utf8(s, MAX_TAG_BYTES));

    // Iterate affected[].
    let mut affected = Vec::new();
    if let Some(arr) = v.get("affected").and_then(|a| a.as_array()) {
        for entry in arr {
            let ecosystem = entry
                .get("package")
                .and_then(|p| p.get("ecosystem"))
                .and_then(|s| s.as_str())
                .map(String::from);
            let package = entry
                .get("package")
                .and_then(|p| p.get("name"))
                .and_then(|s| s.as_str())
                .map(String::from);
            // Only record blocks with both ecosystem AND name. Records that
            // describe only an upstream git repo (no ecosystem package) skip
            // here and are still useful for host-IoC extraction below.
            if let (Some(ecosystem), Some(package)) = (ecosystem, package) {
                let mut subset = serde_json::Map::new();
                if let Some(versions) = entry.get("versions") {
                    subset.insert("versions".to_string(), versions.clone());
                } else {
                    subset.insert("versions".to_string(), Value::Array(Vec::new()));
                }
                if let Some(ranges) = entry.get("ranges") {
                    subset.insert("ranges".to_string(), ranges.clone());
                } else {
                    subset.insert("ranges".to_string(), Value::Array(Vec::new()));
                }
                let versions_json = serde_json::to_string(&Value::Object(subset))
                    .expect("Map<String, Value> is always serializable");
                affected.push(AffectedBlock {
                    ecosystem,
                    package,
                    versions_json,
                });
            }
        }
    }

    let host_iocs = extract_host_iocs(&v);

    Ok(ParsedRecord {
        advisory_id,
        schema_version_observed,
        published_ms,
        severity,
        tag,
        affected,
        host_iocs,
        raw: v,
    })
}

/// Extract host IoCs from an OSV record per the 04-SPIKE-RESULTS.md A4
/// directive: `database_specific.iocs.{domains,ips}` are default-included;
/// `database_specific.iocs.urls[]` is intentionally NOT consulted (over-block
/// risk for legitimate hosts named in malicious-packages records like
/// `discord.com`, `cdn.discordapp.com`, `dl.dropbox.com`). The speculative
/// speculative keys (`malicious_hosts`, `c2`, `exfil_hosts`) DO NOT
/// exist in real data and are intentionally NOT looked up.
///
/// SECONDARY: `references[].type IN ('EVIDENCE', 'REPORT')` → URL host via
/// `url::Url::host_str()`. Empirically rare but not nothing (7/200 EVIDENCE,
/// 0/200 REPORT in the Wave 0 sampling).
pub fn extract_host_iocs(record: &Value) -> Vec<String> {
    let mut out = Vec::new();

    // Primary: database_specific.iocs.{domains,ips}.
    if let Some(iocs) = record.get("database_specific").and_then(|d| d.get("iocs")) {
        push_string_array(&mut out, iocs.get("domains"));
        push_string_array(&mut out, iocs.get("ips"));
        // TODO(v2): re-enable iocs.urls[] extraction once over-block testing
        // confirms safety. Per 04-SPIKE-RESULTS.md A4 + RESEARCH.md Open
        // Question 2: urls include legitimate hosts (discord.com,
        // cdn.discordapp.com, dl.dropbox.com) that would over-block benign
        // installs through the FeedDeny tier.
    }

    // Secondary: references[].type IN ('EVIDENCE', 'REPORT') → URL host.
    if let Some(refs) = record.get("references").and_then(|r| r.as_array()) {
        for r in refs {
            let t = r.get("type").and_then(|s| s.as_str()).unwrap_or("");
            if matches!(t, "EVIDENCE" | "REPORT") {
                if let Some(url_str) = r.get("url").and_then(|s| s.as_str()) {
                    if let Ok(parsed) = url::Url::parse(url_str) {
                        if let Some(host) = parsed.host_str() {
                            out.push(host.to_string());
                        }
                    }
                }
            }
        }
    }

    // Cap host length, drop empties, dedup.
    out.retain(|h| !h.is_empty() && h.len() <= MAX_HOST_IOC_LEN);
    out.sort();
    out.dedup();
    out
}

fn push_string_array(out: &mut Vec<String>, v: Option<&Value>) {
    if let Some(arr) = v.and_then(|x| x.as_array()) {
        for s in arr {
            if let Some(s) = s.as_str() {
                out.push(s.to_string());
            }
        }
    }
}

/// Parse the major+minor part of a SemVer-shaped string (`"1.4.0"` →
/// `Some((1, 4))`). Returns `None` if the first two segments aren't u32-parseable.
fn parse_semver_pair(s: &str) -> Option<(u32, u32)> {
    let mut it = s.split('.');
    let maj: u32 = it.next()?.parse().ok()?;
    let min: u32 = it.next()?.parse().ok()?;
    Some((maj, min))
}

/// UTF-8-safe truncation by byte length: backs off to the prior char boundary
/// rather than slicing inside a multibyte sequence (which would panic).
fn truncate_utf8(s: &str, max_bytes: usize) -> String {
    if s.len() <= max_bytes {
        return s.to_string();
    }
    let mut end = max_bytes;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    s[..end].to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Minimum-viable GHSA record with schema_version 1.4.0.
    fn ghsa_record_1_4_0() -> &'static [u8] {
        br#"{
            "schema_version": "1.4.0",
            "id": "GHSA-mrqg-mwh7-q94j",
            "modified": "2026-01-15T00:00:00Z",
            "published": "2026-01-15T00:00:00Z",
            "summary": "Cross-site scripting in some-pkg",
            "affected": [{"package": {"ecosystem": "npm", "name": "some-pkg"}, "versions": ["1.0.0"]}]
        }"#
    }

    /// MAL-shaped record with schema_version 1.7.4 and database_specific.iocs.
    fn mal_record_1_7_4() -> &'static [u8] {
        br#"{
            "schema_version": "1.7.4",
            "id": "MAL-2026-808",
            "modified": "2026-01-15T00:00:00Z",
            "published": "2026-01-15T00:00:00Z",
            "summary": "Malicious package mal-pkg exfiltrates credentials",
            "affected": [{"package": {"ecosystem": "npm", "name": "mal-pkg"}, "versions": ["1.0.0"]}],
            "database_specific": {
                "iocs": {
                    "domains": ["honey.zakura-int.workers.dev", "exfil.example.com"],
                    "urls": ["https://discord.com/api/webhooks/123"],
                    "ips": ["35.170.187.220"]
                }
            }
        }"#
    }

    #[test]
    fn parser_accepts_schema_version_1_4_0_ghsa() {
        let p = parse_osv_record(ghsa_record_1_4_0(), "GHSA").expect("parse 1.4.0");
        assert_eq!(p.advisory_id, "GHSA-mrqg-mwh7-q94j");
        assert_eq!(p.schema_version_observed, "1.4.0");
        assert_eq!(p.affected.len(), 1);
        assert_eq!(p.affected[0].ecosystem, "npm");
        assert_eq!(p.affected[0].package, "some-pkg");
        assert!(p.affected[0].versions_json.contains("1.0.0"));
    }

    #[test]
    fn parser_accepts_schema_version_1_7_4_mal() {
        let p = parse_osv_record(mal_record_1_7_4(), "OSV").expect("parse 1.7.4");
        assert_eq!(p.advisory_id, "MAL-2026-808");
        assert_eq!(p.schema_version_observed, "1.7.4");
        assert_eq!(p.affected.len(), 1);
        assert_eq!(p.affected[0].package, "mal-pkg");
    }

    #[test]
    fn parser_rejects_schema_version_2_0_0_loud() {
        let body = br#"{"schema_version":"2.0.0","id":"X-1","affected":[]}"#;
        let err = parse_osv_record(body, "OSV").expect_err("must reject");
        match err {
            FeedParseError::SchemaUnknown { observed } => {
                assert_eq!(observed.as_deref(), Some("2.0.0"));
            }
            other => panic!("expected SchemaUnknown, got {other:?}"),
        }
    }

    #[test]
    fn parser_rejects_schema_version_1_3_0_loud() {
        let body = br#"{"schema_version":"1.3.0","id":"X-1","affected":[]}"#;
        let err = parse_osv_record(body, "OSV").expect_err("must reject");
        assert!(matches!(err, FeedParseError::SchemaUnknown { .. }));
    }

    #[test]
    fn parser_rejects_schema_version_missing() {
        let body = br#"{"id":"X-1","affected":[]}"#;
        let err = parse_osv_record(body, "OSV").expect_err("must reject");
        match err {
            FeedParseError::SchemaUnknown { observed } => {
                assert!(observed.is_none(), "missing field reports None");
            }
            other => panic!("expected SchemaUnknown, got {other:?}"),
        }
    }

    #[test]
    fn parser_rejects_oversized_record() {
        let big = vec![b' '; MAX_OSV_RECORD_BYTES + 1];
        let err = parse_osv_record(&big, "OSV").expect_err("must reject");
        match err {
            FeedParseError::OversizedRecord { bytes, cap } => {
                assert!(bytes > cap);
            }
            other => panic!("expected OversizedRecord, got {other:?}"),
        }
    }

    #[test]
    fn parser_extracts_domains_and_ips_skips_urls() {
        let p = parse_osv_record(mal_record_1_7_4(), "OSV").expect("parse");
        // Two domains + one ip = 3. urls intentionally NOT extracted.
        // (Sorted + deduped.)
        assert_eq!(p.host_iocs.len(), 3);
        assert!(p.host_iocs.contains(&"honey.zakura-int.workers.dev".to_string()));
        assert!(p.host_iocs.contains(&"exfil.example.com".to_string()));
        assert!(p.host_iocs.contains(&"35.170.187.220".to_string()));
        // Critical: discord.com (from urls[]) MUST NOT appear.
        assert!(
            !p.host_iocs.contains(&"discord.com".to_string()),
            "iocs.urls[] hosts must NOT be extracted in v1 (over-block risk)"
        );
    }

    #[test]
    fn parser_extracts_evidence_references_secondary() {
        let body = br#"{
            "schema_version": "1.7.4",
            "id": "MAL-2026-EVIDENCE",
            "affected": [],
            "references": [
                {"type": "EVIDENCE", "url": "https://evidence.example.com/post/1"},
                {"type": "REPORT", "url": "https://nvd.nist.gov/vuln/CVE-2026-0"},
                {"type": "WEB", "url": "https://github.com/foo/bar"}
            ]
        }"#;
        let p = parse_osv_record(body, "OSV").expect("parse");
        // EVIDENCE + REPORT extracted; WEB skipped.
        assert!(p.host_iocs.contains(&"evidence.example.com".to_string()));
        assert!(p.host_iocs.contains(&"nvd.nist.gov".to_string()));
        assert!(!p.host_iocs.contains(&"github.com".to_string()));
    }

    #[test]
    fn parser_skips_speculative_field_names() {
        // Speculated database_specific.malicious_hosts /
        // c2 / exfil_hosts. Empirical sampling shows zero occurrences across
        // 200 records (RESEARCH.md Pitfall 4). A record carrying only the
        // speculative names extracts nothing.
        let body = br#"{
            "schema_version": "1.7.4",
            "id": "MAL-2026-SPECULATIVE",
            "affected": [],
            "database_specific": {
                "malicious_hosts": ["should-not-be-extracted.example.com"],
                "c2": ["c2-1.example.com"],
                "exfil_hosts": ["exfil-1.example.com"]
            }
        }"#;
        let p = parse_osv_record(body, "OSV").expect("parse");
        assert_eq!(
            p.host_iocs.len(),
            0,
            "speculative names must NOT match real-data extraction logic"
        );
    }

    #[test]
    fn parser_truncates_oversized_tag_to_64_chars() {
        let summary = "x".repeat(200);
        let body = format!(
            r#"{{
                "schema_version": "1.7.4",
                "id": "MAL-2026-LONGSUMMARY",
                "summary": "{summary}",
                "affected": []
            }}"#
        );
        let p = parse_osv_record(body.as_bytes(), "OSV").expect("parse");
        assert_eq!(p.tag.as_deref().map(str::len), Some(MAX_TAG_BYTES));
    }

    #[test]
    fn parser_caps_advisory_id_length() {
        let id = "X".repeat(MAX_ADVISORY_ID_LEN + 1);
        let body = format!(
            r#"{{
                "schema_version": "1.7.4",
                "id": "{id}",
                "affected": []
            }}"#
        );
        let err = parse_osv_record(body.as_bytes(), "OSV").expect_err("must reject");
        assert!(matches!(err, FeedParseError::InvalidAdvisoryId { .. }));
    }

    #[test]
    fn parser_extracts_first_seen_from_published() {
        let p = parse_osv_record(mal_record_1_7_4(), "OSV").expect("parse");
        // 2026-01-15T00:00:00Z = 1768435200000 ms (verified via
        // `python3 -c "from datetime import datetime, timezone;
        // print(int(datetime(2026,1,15,0,0,0,tzinfo=timezone.utc).timestamp()*1000))"`).
        assert_eq!(p.published_ms, 1768435200000);
    }

    #[test]
    fn matcher_reexports_osv_match_from_core() {
        // Verify the re-export shim resolves correctly. If matcher.rs broke
        // its `pub use sentinel_core::osv_match::*`, this fails to compile.
        use crate::feed::matcher::{version_in_affected_block, Range, RangeType};
        let no_ranges: Vec<Range> = Vec::new();
        let versions = vec!["1.0.0".to_string()];
        assert!(version_in_affected_block("1.0.0", &versions, &no_ranges));
        // Compile-time check that RangeType is in scope.
        let _ = RangeType::Semver;
    }

    #[test]
    fn parser_host_iocs_dedup_and_sorted() {
        let body = br#"{
            "schema_version": "1.7.4",
            "id": "MAL-2026-DUP",
            "affected": [],
            "database_specific": {
                "iocs": {
                    "domains": ["b.example.com", "a.example.com", "a.example.com"],
                    "ips": ["1.2.3.4"]
                }
            }
        }"#;
        let p = parse_osv_record(body, "OSV").expect("parse");
        assert_eq!(
            p.host_iocs,
            vec![
                "1.2.3.4".to_string(),
                "a.example.com".to_string(),
                "b.example.com".to_string(),
            ]
        );
    }

    #[test]
    fn parser_drops_oversized_host_ioc() {
        let big_host = "h".repeat(MAX_HOST_IOC_LEN + 1);
        let body = format!(
            r#"{{
                "schema_version": "1.7.4",
                "id": "MAL-2026-BIGHOST",
                "affected": [],
                "database_specific": {{
                    "iocs": {{
                        "domains": ["{big_host}", "ok.example.com"]
                    }}
                }}
            }}"#
        );
        let p = parse_osv_record(body.as_bytes(), "OSV").expect("parse");
        assert!(!p.host_iocs.iter().any(|h| h.len() > MAX_HOST_IOC_LEN));
        assert!(p.host_iocs.contains(&"ok.example.com".to_string()));
    }
}
