//! Curated default allowlist + abuse-pattern denies.
//!
//! Source: `crates/sentinel-core/data/allowlist.yaml` (D-23 — in-tree YAML
//! compiled into the daemon at build time via include_str!). Loaded once at
//! daemon startup. Entries are tagged with the appropriate RuleTier
//! (BuiltinDeny for kind:deny, CuratedAllow for kind:allow) and the daemon
//! merges them with project/user rules at PrepareSnapshot time (plan 02-06).

use sentinel_core::{AllowlistEntry, MatchType, RuleKind, RuleTier};
use serde::Deserialize;

pub const CURATED_YAML_PATH: &str = "crates/sentinel-core/data/allowlist.yaml";

/// Compile-time embed. The path is relative to this source file; the literal
/// `../../sentinel-core/data/allowlist.yaml` resolves from
/// `crates/sentinel-daemon/src/curated.rs` to the in-tree YAML.
const CURATED_YAML: &str = include_str!("../../sentinel-core/data/allowlist.yaml");

/// Minimum length for a suffix pattern (e.g. `.x.y` = 4 bytes is the smallest
/// reasonable form). Anything shorter is over-broad (e.g. `.com` was the
/// classic mistake) — reject at load time so the YAML PR review never accepts.
pub const MIN_SUFFIX_LEN: usize = 4;

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
///   - kind: deny  → tier: BuiltinDeny  (non-overridable per D-26)
///   - kind: allow → tier: CuratedAllow (beats feed-deny per POL-06)
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
