//! Deterministic snapshot construction.
//!
//! The daemon and CLI both need to derive identical snapshot bytes from the
//! same trusted inputs. Keep clock/RNG and input discovery outside this module:
//! callers supply `run_uuid`, `generated_at_unix_ms`, and already-verified rule
//! vectors. This module only applies deterministic filtering, merging, and
//! ordering.

use std::collections::BTreeSet;

use crate::{AllowlistEntry, Snapshot, SCHEMA_V2};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SnapshotBuildInput {
    pub run_uuid: String,
    pub generated_at_unix_ms: i64,
    pub curated_entries: Vec<AllowlistEntry>,
    pub disabled_curated_patterns: BTreeSet<String>,
    pub verified_user_entries: Vec<AllowlistEntry>,
    pub lockfile_entries: Vec<AllowlistEntry>,
}

pub fn build_snapshot(input: SnapshotBuildInput) -> Snapshot {
    let SnapshotBuildInput {
        run_uuid,
        generated_at_unix_ms,
        curated_entries,
        disabled_curated_patterns,
        verified_user_entries,
        lockfile_entries,
    } = input;

    let mut entries = Vec::with_capacity(
        curated_entries.len() + verified_user_entries.len() + lockfile_entries.len(),
    );
    entries.extend(
        curated_entries
            .into_iter()
            .filter(|entry| !disabled_curated_patterns.contains(&entry.pattern)),
    );
    entries.extend(verified_user_entries);
    entries.extend(lockfile_entries);
    entries.sort_by_key(|entry| entry.tier);

    Snapshot {
        schema_version: SCHEMA_V2,
        generated_at_unix_ms,
        entries,
        run_uuid: Some(run_uuid),
    }
}

pub fn build_snapshot_bytes(input: SnapshotBuildInput) -> Result<Vec<u8>, crate::Error> {
    build_snapshot(input).encode()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{AllowlistEntry, MatchType, RuleKind, RuleTier};

    fn entry(pattern: &str, tier: RuleTier) -> AllowlistEntry {
        AllowlistEntry {
            kind: RuleKind::Allow,
            tier,
            match_type: MatchType::Exact,
            pattern: pattern.to_string(),
            reason: format!("reason for {pattern}"),
        }
    }

    fn input() -> SnapshotBuildInput {
        SnapshotBuildInput {
            run_uuid: "run-1".to_string(),
            generated_at_unix_ms: 1_700_000_000_000,
            curated_entries: vec![
                entry("registry.npmjs.org", RuleTier::CuratedAllow),
                entry("blocked.example", RuleTier::ConfirmedDeny),
            ],
            disabled_curated_patterns: BTreeSet::new(),
            verified_user_entries: vec![entry("user.example", RuleTier::UserAllow)],
            lockfile_entries: vec![entry("lockfile.example", RuleTier::CuratedAllow)],
        }
    }

    #[test]
    fn build_snapshot_is_byte_deterministic() {
        let a = build_snapshot_bytes(input()).unwrap();
        let b = build_snapshot_bytes(input()).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn disabled_curated_entries_are_removed() {
        let mut input = input();
        input
            .disabled_curated_patterns
            .insert("blocked.example".to_string());
        let snapshot = build_snapshot(input);
        assert!(!snapshot
            .entries
            .iter()
            .any(|entry| entry.pattern == "blocked.example"));
        assert!(snapshot
            .entries
            .iter()
            .any(|entry| entry.pattern == "user.example"));
    }

    #[test]
    fn entries_are_sorted_by_tier() {
        let snapshot = build_snapshot(input());
        let tiers: Vec<RuleTier> = snapshot.entries.iter().map(|entry| entry.tier).collect();
        let mut sorted = tiers.clone();
        sorted.sort();
        assert_eq!(tiers, sorted);
    }
}
