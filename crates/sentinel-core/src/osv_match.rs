//! OSV-schema version-range matcher (D-91).
//!
//! Implements `affected[].versions[]` exact-match plus `affected[].ranges[]`
//! event walking for SEMVER and ECOSYSTEM types. GIT type returns false (no
//! commit-graph access).
//!
//! Lives in sentinel-core (not sentinel-daemon) so log-write enrichment AND
//! parse-time filtering can both call the same evaluator. Reference:
//! <https://ossf.github.io/osv-schema/#range>.
//!
//! Per OSV-schema event semantics:
//!   - SEMVER: parse versions via SemVer 2.0 (no leading "v"); walk events in
//!     order; flip an in_range flag based on introduced / fixed / last_affected.
//!   - ECOSYSTEM: events carry uninterpreted strings; we cannot soundly
//!     compare without ecosystem-specific knowledge, so version_in_range
//!     returns false. The caller MUST consult `affected[].versions[]` exact
//!     match (handled by `version_in_affected_block`).
//!   - GIT: requires commit-graph; we don't have one. Always false. Conservative
//!     under-match is preferred over false-positive vulnerability attribution.

use semver::Version;
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum RangeType {
    Semver,
    Ecosystem,
    Git,
}

/// OSV `affected[].ranges[].events[]` shape — each event is a
/// single-key object: `{"introduced": "1.0.0"}` etc. The `tag` value is
/// the event type, the `value` is the version literal.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Event {
    Introduced(String),
    Fixed(String),
    LastAffected(String),
    /// GIT-only per OSV spec. Ignored in SEMVER/ECOSYSTEM walks.
    Limit(String),
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Range {
    #[serde(rename = "type")]
    pub range_type: RangeType,
    pub events: Vec<Event>,
}

/// Returns true iff `version` falls inside `range`'s event walk.
pub fn version_in_range(version: &str, range: &Range) -> bool {
    match range.range_type {
        RangeType::Semver => semver_in_range(version, &range.events),
        RangeType::Ecosystem => ecosystem_in_range(version, &range.events),
        // GIT requires the commit graph of the affected repo (which we don't
        // have). Conservative: never match. Callers should rely on
        // `affected[].versions[]` exact match for GIT-typed advisories.
        RangeType::Git => false,
    }
}

fn semver_in_range(version: &str, events: &[Event]) -> bool {
    let v = match Version::parse(version) {
        Ok(v) => v,
        Err(_) => return false,
    };
    let mut in_range = false;
    for e in events {
        match e {
            Event::Introduced(s) => {
                if s == "0" {
                    in_range = true;
                } else if let Ok(b) = Version::parse(s) {
                    if v >= b {
                        in_range = true;
                    }
                }
            }
            Event::Fixed(s) => {
                if let Ok(b) = Version::parse(s) {
                    if v >= b {
                        in_range = false;
                    }
                }
            }
            Event::LastAffected(s) => {
                if let Ok(b) = Version::parse(s) {
                    if v > b {
                        in_range = false;
                    }
                }
            }
            // Limit applies to GIT ranges per OSV spec; ignore here.
            Event::Limit(_) => {}
        }
    }
    in_range
}

/// ECOSYSTEM range type carries uninterpreted strings per OSV spec; we cannot
/// order them without ecosystem-specific knowledge. Conservative: always
/// false. Callers must rely on `affected[].versions[]` exact match (which
/// `version_in_affected_block` consults first).
fn ecosystem_in_range(_version: &str, _events: &[Event]) -> bool {
    false
}

/// Combined check: exact match against `affected_versions[]` (covers both
/// SEMVER and ECOSYSTEM enumeration), then walk `affected_ranges[]`.
pub fn version_in_affected_block(
    version: &str,
    affected_versions: &[String],
    affected_ranges: &[Range],
) -> bool {
    if affected_versions.iter().any(|v| v == version) {
        return true;
    }
    affected_ranges.iter().any(|r| version_in_range(version, r))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn semver_range(events: Vec<Event>) -> Range {
        Range {
            range_type: RangeType::Semver,
            events,
        }
    }

    fn ecosystem_range(events: Vec<Event>) -> Range {
        Range {
            range_type: RangeType::Ecosystem,
            events,
        }
    }

    fn git_range(events: Vec<Event>) -> Range {
        Range {
            range_type: RangeType::Git,
            events,
        }
    }

    #[test]
    fn osv_match_semver_introduced_zero_fixed() {
        // Walk: in_range=false -> Introduced("0") -> true -> Fixed("2.0.0") on v
        // >= 2.0.0 -> false again.
        let r = semver_range(vec![
            Event::Introduced("0".into()),
            Event::Fixed("2.0.0".into()),
        ]);
        assert!(version_in_range("1.5.0", &r));
        assert!(!version_in_range("2.0.0", &r), "fixed bound is exclusive");
        assert!(!version_in_range("2.0.1", &r));
    }

    #[test]
    fn osv_match_semver_last_affected() {
        let r = semver_range(vec![
            Event::Introduced("1.0.0".into()),
            Event::LastAffected("1.5.0".into()),
        ]);
        assert!(version_in_range("1.5.0", &r), "last_affected is inclusive");
        assert!(!version_in_range("1.6.0", &r));
        assert!(!version_in_range("0.9.0", &r), "before introduced");
    }

    #[test]
    fn osv_match_ecosystem_versions_list_only() {
        // ECOSYSTEM range walker returns false unconditionally — caller MUST
        // exact-match against affected[].versions[]. version_in_affected_block
        // does that.
        let versions = vec!["1.0.0".to_string(), "1.0.1".to_string()];
        let r = ecosystem_range(vec![
            Event::Introduced("1.0.0".into()),
            Event::Fixed("2.0.0".into()),
        ]);
        assert!(version_in_affected_block(
            "1.0.0",
            &versions,
            &[r.clone()]
        ));
        assert!(!version_in_affected_block("1.0.2", &versions, &[r]));
    }

    #[test]
    fn osv_match_git_type_never_matches() {
        let r = git_range(vec![
            Event::Introduced("0".into()),
            Event::Fixed("abcdef".into()),
        ]);
        assert!(!version_in_range("1.0.0", &r));
        // GIT remains false even when caller passes versions[] — wait, the
        // caller's exact-match should still win. Verify:
        let versions = vec!["1.0.0".to_string()];
        assert!(version_in_affected_block(
            "1.0.0",
            &versions,
            &[r.clone()]
        ));
        assert!(!version_in_affected_block("1.0.1", &versions, &[r]));
    }

    #[test]
    fn osv_match_invalid_semver_returns_false() {
        let r = semver_range(vec![
            Event::Introduced("0".into()),
            Event::Fixed("2.0.0".into()),
        ]);
        assert!(!version_in_range("not-a-version", &r));
    }

    #[test]
    fn osv_match_introduced_only_open_ended() {
        // No fixed/last_affected — every version >= introduced matches.
        let r = semver_range(vec![Event::Introduced("1.0.0".into())]);
        assert!(version_in_range("1.0.0", &r));
        assert!(version_in_range("99.0.0", &r));
        assert!(!version_in_range("0.9.0", &r));
    }

    #[test]
    fn osv_match_affected_block_versions_exact_match_wins() {
        // Exact match in affected_versions[] wins even when ranges would not
        // match.
        let versions = vec!["1.2.3".to_string()];
        let no_ranges: Vec<Range> = Vec::new();
        assert!(version_in_affected_block("1.2.3", &versions, &no_ranges));
        assert!(!version_in_affected_block("1.2.4", &versions, &no_ranges));
    }

    #[test]
    fn osv_match_pre_release_ordering_correct() {
        // SemVer 2.0: 1.0.0-rc.1 < 1.0.0. The semver crate handles this.
        let r = semver_range(vec![
            Event::Introduced("0".into()),
            Event::Fixed("1.0.0".into()),
        ]);
        assert!(version_in_range("1.0.0-rc.1", &r));
        assert!(!version_in_range("1.0.0", &r));
    }
}
