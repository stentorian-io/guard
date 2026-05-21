//! Curated default allowlist + abuse-pattern denies + feed IOCs.
//!
//! Source: `crates/guard-core/data/{trusted-registry,malicious,suspicious}-*.yaml`
//! (in-tree YAML assembled and converted to JSON by build.rs at compile time).
//! Loaded once at daemon startup. Entries are tagged with the appropriate
//! RuleTier (BuiltinDeny for kind:deny, CuratedAllow for kind:allow) and the
//! daemon merges them with project/user rules at PrepareSnapshot time.

use guard_core::{AllowlistEntry, MatchType, RuleKind, RuleTier};
use serde::Deserialize;

pub const CURATED_DATA_DIR: &str = "crates/guard-core/data";

const CURATED_JSON: &str = include_str!(concat!(env!("OUT_DIR"), "/rules_combined.json"));

/// Minimum length for a suffix pattern. WARNING fix (v0.2 review):
/// raised from 4 → 6 so single-TLD suffixes like `.com`, `.org`, `.net`,
/// `.dev`, `.app` (all 4 bytes) are rejected at load time. Real curated
/// patterns like `.co.uk` (6), `.bar.io` (7), `.npmjs.org` (10) all pass.
/// The previous 4-byte limit accidentally allowed `.com` to slip through,
/// which would match every `.com` host on the internet — exactly the
/// catastrophic over-broadening the constant exists to prevent.
pub const MIN_SUFFIX_LEN: usize = 6;

#[derive(Debug, thiserror::Error)]
pub enum CuratedError {
    #[error("parse: {0}")]
    Parse(String),
    #[error("invalid pattern at index {index}: {reason}")]
    InvalidPattern { index: usize, reason: String },
}

#[derive(Debug, Deserialize)]
struct EntriesFile {
    entries: Vec<RawEntry>,
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Confidence {
    Confirmed,
    Suspect,
}

#[derive(Debug, Deserialize)]
struct RawEntry {
    kind: RuleKind,
    #[serde(rename = "match")]
    match_type: MatchType,
    pattern: String,
    reason: String,
    confidence: Option<Confidence>,
}

/// Load the build-time-embedded JSON (converted from YAML by build.rs).
pub fn load_curated() -> Result<Vec<AllowlistEntry>, CuratedError> {
    parse_entries(CURATED_JSON)
}

fn parse_entries(json: &str) -> Result<Vec<AllowlistEntry>, CuratedError> {
    let file: EntriesFile =
        serde_json::from_str(json).map_err(|e| CuratedError::Parse(e.to_string()))?;
    validate_entries(file.entries)
}

/// Pure YAML parser — available only in tests for adversarial fixtures.
#[cfg(any(test, feature = "test-yaml"))]
pub fn parse_yaml(yaml: &str) -> Result<Vec<AllowlistEntry>, CuratedError> {
    let file: EntriesFile =
        serde_yml::from_str(yaml).map_err(|e| CuratedError::Parse(e.to_string()))?;
    validate_entries(file.entries)
}

fn validate_entries(entries: Vec<RawEntry>) -> Result<Vec<AllowlistEntry>, CuratedError> {
    let mut out = Vec::with_capacity(entries.len());
    for (i, e) in entries.into_iter().enumerate() {
        if e.reason.trim().is_empty() {
            return Err(CuratedError::InvalidPattern {
                index: i,
                reason: "reason field is empty".into(),
            });
        }
        if matches!(e.match_type, MatchType::Suffix) {
            if !e.pattern.starts_with('.') {
                return Err(CuratedError::InvalidPattern {
                    index: i,
                    reason: format!("suffix pattern must start with '.': {}", e.pattern),
                });
            }
            if e.pattern.len() < MIN_SUFFIX_LEN {
                return Err(CuratedError::InvalidPattern {
                    index: i,
                    reason: format!(
                        "suffix pattern too short (over-broad): {} (min {} bytes)",
                        e.pattern, MIN_SUFFIX_LEN
                    ),
                });
            }
        }
        let tier = match (e.kind, e.confidence) {
            (RuleKind::Allow, _) => RuleTier::CuratedAllow,
            (RuleKind::Deny, Some(Confidence::Confirmed)) => RuleTier::ConfirmedDeny,
            (RuleKind::Deny, Some(Confidence::Suspect)) => RuleTier::SuspectDeny,
            (RuleKind::Deny, None) => RuleTier::BuiltinDeny,
        };
        out.push(AllowlistEntry {
            kind: e.kind,
            tier,
            match_type: e.match_type,
            pattern: e.pattern,
            reason: e.reason,
        });
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use guard_core::RuleTier;

    #[test]
    fn confirmed_deny_maps_to_confirmed_deny_tier() {
        let yaml = r#"
entries:
  - kind: deny
    match: exact
    pattern: evil.com
    reason: "MAL-2026-001 supply-chain IOC (FEED)"
    confidence: confirmed
"#;
        let entries = parse_yaml(yaml).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].tier, RuleTier::ConfirmedDeny);
    }

    #[test]
    fn suspect_deny_maps_to_suspect_deny_tier() {
        let yaml = r#"
entries:
  - kind: deny
    match: exact
    pattern: sketchy.io
    reason: "MAL-2026-002 supply-chain IOC (FEED)"
    confidence: suspect
"#;
        let entries = parse_yaml(yaml).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].tier, RuleTier::SuspectDeny);
    }

    #[test]
    fn deny_without_confidence_maps_to_builtin_deny() {
        let yaml = r#"
entries:
  - kind: deny
    match: suffix
    pattern: .workers.dev
    reason: "Cloudflare Workers C2 pattern"
"#;
        let entries = parse_yaml(yaml).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].tier, RuleTier::BuiltinDeny);
    }

    #[test]
    fn allow_ignores_confidence_field() {
        let yaml = r#"
entries:
  - kind: allow
    match: exact
    pattern: registry.npmjs.org
    reason: "npm registry"
    confidence: confirmed
"#;
        let entries = parse_yaml(yaml).unwrap();
        assert_eq!(entries[0].tier, RuleTier::CuratedAllow);
    }

    #[test]
    fn mixed_confidence_tiers_sort_correctly() {
        let yaml = r#"
entries:
  - kind: deny
    match: exact
    pattern: confirmed-c2.example.com
    reason: "MAL-001 (FEED)"
    confidence: confirmed
  - kind: deny
    match: exact
    pattern: suspect-c2.example.com
    reason: "MAL-002 (FEED)"
    confidence: suspect
  - kind: deny
    match: suffix
    pattern: .workers.dev
    reason: "Cloudflare Workers C2 pattern"
  - kind: allow
    match: exact
    pattern: registry.npmjs.org
    reason: "npm registry"
"#;
        let mut entries = parse_yaml(yaml).unwrap();
        entries.sort_by_key(|e| e.tier);
        assert_eq!(entries[0].tier, RuleTier::BuiltinDeny);
        assert_eq!(entries[1].tier, RuleTier::CuratedAllow);
        assert_eq!(entries[2].tier, RuleTier::ConfirmedDeny);
        assert_eq!(entries[3].tier, RuleTier::SuspectDeny);
    }
}
