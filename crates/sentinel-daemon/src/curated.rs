//! Curated default allowlist + abuse-pattern denies + feed IOCs.
//!
//! Source: `crates/sentinel-core/data/{allow,deny}/*.yaml` (in-tree YAML
//! assembled into a single blob by build.rs at compile time). Loaded once at
//! daemon startup. Entries are tagged with the appropriate RuleTier
//! (BuiltinDeny for kind:deny, CuratedAllow for kind:allow) and the daemon
//! merges them with project/user rules at PrepareSnapshot time.

use sentinel_core::{AllowlistEntry, MatchType, RuleKind, RuleTier};
use serde::Deserialize;

pub const CURATED_DATA_DIR: &str = "crates/sentinel-core/data";

const CURATED_YAML: &str = include_str!(concat!(env!("OUT_DIR"), "/rules_combined.yaml"));

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
    #[error("yaml parse: {0}")]
    Parse(String),
    #[error("invalid pattern at index {index}: {reason}")]
    InvalidPattern { index: usize, reason: String },
}

#[derive(Debug, Deserialize)]
struct YamlFile {
    entries: Vec<YamlEntry>,
}

#[derive(Debug, Deserialize)]
struct YamlEntry {
    kind: RuleKind,
    #[serde(rename = "match")]
    match_type: MatchType,
    pattern: String,
    reason: String,
}

/// Parse the embedded YAML. Tier is assigned from `kind`:
///   - kind: deny  → tier: BuiltinDeny  (non-overridable)
///   - kind: allow → tier: CuratedAllow (beats feed-deny by tier ordering)
pub fn load_curated() -> Result<Vec<AllowlistEntry>, CuratedError> {
    parse_yaml(CURATED_YAML)
}

/// Pure parser — useful for tests with adversarial fixtures.
pub fn parse_yaml(yaml: &str) -> Result<Vec<AllowlistEntry>, CuratedError> {
    let file: YamlFile =
        serde_yml::from_str(yaml).map_err(|e| CuratedError::Parse(e.to_string()))?;

    let mut out = Vec::with_capacity(file.entries.len());
    for (i, e) in file.entries.into_iter().enumerate() {
        // Validate reason non-empty.
        if e.reason.trim().is_empty() {
            return Err(CuratedError::InvalidPattern {
                index: i,
                reason: "reason field is empty".into(),
            });
        }
        // Validate suffix patterns.
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
        let tier = match e.kind {
            RuleKind::Deny => RuleTier::BuiltinDeny,
            RuleKind::Allow => RuleTier::CuratedAllow,
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
