//! Allowlist entry types and per-entry evaluator.
//!
//! Phase 2 redesign per D-24 + RESEARCH.md §2 / §5 tier ordering. Replaces the
//! Phase 1 enum (Exact|Suffix|Ip variants) with a single struct carrying:
//!   - kind: allow | deny       (D-24 — both directions in one type)
//!   - tier: priority class     (D-25/D-26/D-27 — non-overridable builtin denies + POL-06)
//!   - match_type: exact | suffix | ip
//!   - pattern: the host or IP literal
//!   - reason: required, surfaced in block-log attribution
//!
//! Suffix matching is byte-wise and REQUIRES patterns to start with `.` —
//! a pattern `.workers.dev` matches `foo.workers.dev` but NOT `workers.dev`
//! and NOT `notworkers.dev`. This is the D-16 invariant carried forward.

use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RuleKind {
    Allow,
    Deny,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum MatchType {
    Exact,
    Suffix,
    Ip,
}

/// Priority tier — daemon pre-sorts the snapshot's `entries` Vec so the dylib
/// iterates a flat slice and returns at the FIRST matching entry. The numeric
/// ordering implements RESEARCH.md §5 precedence:
///
///   Tier 0: BuiltinDeny       (YAML kind:deny, non-overridable D-26)
///   Tier 1: CuratedAllow      (YAML kind:allow, beats feed-deny POL-06)
///   Tier 2: UserDeny          (SQLite rules kind:deny)
///   Tier 3: FeedDeny          (threat-intel IOCs from OSV/GHSA feeds)
///   Tier 4: UserAllow         (SQLite rules kind:allow)
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[repr(u8)]
pub enum RuleTier {
    BuiltinDeny = 0,
    CuratedAllow = 1,
    UserDeny = 2,
    FeedDeny = 3,
    UserAllow = 4,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AllowlistEntry {
    pub kind: RuleKind,
    pub tier: RuleTier,
    pub match_type: MatchType,
    pub pattern: String,
    pub reason: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Verdict {
    Allow,
    Deny,
}

impl AllowlistEntry {
    /// Bytewise host match. host MUST NOT include port or scheme.
    /// Suffix patterns MUST start with `.`; non-conforming suffix patterns
    /// are treated as no-match (do not silently widen to substring).
    pub fn matches(&self, host: &[u8]) -> bool {
        match self.match_type {
            MatchType::Exact | MatchType::Ip => self.pattern.as_bytes() == host,
            MatchType::Suffix => {
                let pat = self.pattern.as_bytes();
                if pat.first() != Some(&b'.') {
                    return false;
                }
                host.ends_with(pat)
            }
        }
    }
}

/// Single-entry evaluator. Returns Some(Verdict) on match, None on no-match.
/// Plan 02-02 builds the multi-entry tier-walk evaluator on top of this.
pub fn evaluate_rule(entry: &AllowlistEntry, host: &[u8]) -> Option<Verdict> {
    if entry.matches(host) {
        Some(match entry.kind {
            RuleKind::Allow => Verdict::Allow,
            RuleKind::Deny => Verdict::Deny,
        })
    } else {
        None
    }
}
