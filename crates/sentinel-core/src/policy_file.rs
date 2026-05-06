//! `.sentinel.toml` deserde types and parser.
//!
//! D-39 schema:
//!   version = 1
//!
//!   [[rules]]
//!   kind = "allow" | "deny"
//!   match = "exact" | "suffix" | "ip"
//!   pattern = "..."
//!   reason = "..."   # REQUIRED — serde errors on missing
//!
//! `reason` is non-optional by design (D-39): missing reason → parse error →
//! file effectively rejected. Plan 02-03 layers the trust check on top of this
//! parser; the parsed value here is "syntactically valid" but not yet "trusted".

use crate::allowlist::{MatchType, RuleKind};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct SentinelToml {
    pub version: u16,
    #[serde(default)]
    pub rules: Vec<PolicyRule>,
}

#[derive(Debug, Deserialize)]
pub struct PolicyRule {
    pub kind: RuleKind,
    #[serde(rename = "match")]
    pub match_type: MatchType,
    pub pattern: String,
    pub reason: String, // REQUIRED — no Option<>; missing reason produces a serde error
}

#[derive(Debug, thiserror::Error)]
pub enum PolicyFileError {
    #[error("toml parse error: {0}")]
    ParseError(String),
    #[error("unsupported version {0}; only version=1 is accepted")]
    UnsupportedVersion(u16),
}

/// Parse a `.sentinel.toml` content string into a SentinelToml.
/// Validates `version == 1` after deserialization.
pub fn parse(content: &str) -> Result<SentinelToml, PolicyFileError> {
    let parsed: SentinelToml =
        toml::from_str(content).map_err(|e| PolicyFileError::ParseError(e.to_string()))?;
    if parsed.version != 1 {
        return Err(PolicyFileError::UnsupportedVersion(parsed.version));
    }
    Ok(parsed)
}
