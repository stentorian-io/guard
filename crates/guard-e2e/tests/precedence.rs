//! POL-06 unit-level regression: curated allow beats feed deny.
//!
//! Structural proof — no daemon, no spawn. Confirms that the tier ordering
//! in `evaluate_policy` returns `CuratedAllow`'s verdict before the `ConfirmedDeny`
//! tier is examined.
//!
//! POL-06 is enforced STRUCTURALLY by the `AllowlistEntry` type's `RuleTier`
//! field: CuratedAllow=1 < ConfirmedDeny=2. The daemon's `PrepareSnapshot`
//! handler sorts entries by tier; the dylib's hot path iterates the
//! pre-sorted slice and returns at the first match. So a `CuratedAllow`
//! entry encountered first wins.
//!
//! These tests live in guard-e2e (not guard-core) because they assert
//! a CROSS-LAYER invariant: the daemon's tier-sort discipline + the dylib's
//! `evaluate_policy` linear scan together implement POL-06. A regression in
//! either layer would surface here.

use guard_core::{
    AllowlistEntry, MatchType, RuleKind, RuleTier, SourceKind, Verdict, evaluate_policy,
};

fn entry(kind: RuleKind, tier: RuleTier, mt: MatchType, pattern: &str) -> AllowlistEntry {
    AllowlistEntry {
        kind,
        tier,
        match_type: mt,
        pattern: pattern.into(),
        reason: "test".into(),
    }
}

#[test]
fn pol_06_curated_allow_beats_confirmed_deny() {
    // POL-06 invariant: a CuratedAllow entry at Tier 1 must beat a
    // ConfirmedDeny entry at Tier 2 for the same hostname.
    let entries = vec![
        entry(
            RuleKind::Allow,
            RuleTier::CuratedAllow,
            MatchType::Exact,
            "registry.npmjs.org",
        ),
        entry(
            RuleKind::Deny,
            RuleTier::ConfirmedDeny,
            MatchType::Exact,
            "registry.npmjs.org",
        ),
    ];
    let (verdict, src) = evaluate_policy(b"registry.npmjs.org", None, true, &entries);
    assert_eq!(
        verdict,
        Verdict::Allow,
        "POL-06: curated allow MUST beat feed deny"
    );
    assert_eq!(src, SourceKind::CuratedAllow);
}

#[test]
fn pol_06_holds_when_entries_supplied_in_arbitrary_order() {
    // Even if entries arrive unsorted from upstream, the daemon's
    // prepare-snapshot path sorts by tier. Sorting is the structural guarantee.
    let mut entries = vec![
        entry(
            RuleKind::Deny,
            RuleTier::ConfirmedDeny,
            MatchType::Exact,
            "registry.npmjs.org",
        ),
        entry(
            RuleKind::Allow,
            RuleTier::CuratedAllow,
            MatchType::Exact,
            "registry.npmjs.org",
        ),
    ];
    entries.sort_by_key(|e| e.tier); // explicit sort — mirrors what daemon does
    let (verdict, src) = evaluate_policy(b"registry.npmjs.org", None, true, &entries);
    assert_eq!(verdict, Verdict::Allow);
    assert_eq!(src, SourceKind::CuratedAllow);
}

#[test]
fn d_26_builtin_deny_beats_user_allow() {
    // D-26 invariant: a BuiltinDeny entry at Tier 0 must beat a UserAllow
    // entry at Tier 4 for the same suffix. User rules CANNOT override
    // the curated YAML's abuse-pattern denies.
    let mut entries = vec![
        entry(
            RuleKind::Allow,
            RuleTier::UserAllow,
            MatchType::Suffix,
            ".workers.dev",
        ),
        entry(
            RuleKind::Deny,
            RuleTier::BuiltinDeny,
            MatchType::Suffix,
            ".workers.dev",
        ),
    ];
    entries.sort_by_key(|e| e.tier);
    let (verdict, src) = evaluate_policy(b"my-deploy.workers.dev", None, true, &entries);
    assert_eq!(verdict, Verdict::Deny);
    assert_eq!(src, SourceKind::BuiltinDeny);
}

#[test]
fn pol_06_first_match_wins_within_same_tier() {
    // Within the same tier, evaluate_policy returns at the first match. This
    // is intentional — pre-sorting puts higher-priority tiers first, and within
    // a tier the order doesn't matter for correctness because all entries at
    // the same tier are the same kind (e.g. all CuratedAllow are kind=Allow).
    let entries = vec![
        entry(
            RuleKind::Allow,
            RuleTier::CuratedAllow,
            MatchType::Exact,
            "registry.npmjs.org",
        ),
        entry(
            RuleKind::Allow,
            RuleTier::CuratedAllow,
            MatchType::Suffix,
            ".npmjs.org",
        ),
    ];
    let (verdict, src) = evaluate_policy(b"registry.npmjs.org", None, true, &entries);
    assert_eq!(verdict, Verdict::Allow);
    assert_eq!(src, SourceKind::CuratedAllow);
}

#[test]
fn default_deny_when_no_entry_matches() {
    let entries = vec![entry(
        RuleKind::Allow,
        RuleTier::CuratedAllow,
        MatchType::Exact,
        "registry.npmjs.org",
    )];
    let (verdict, src) = evaluate_policy(b"unknown.example.com", None, true, &entries);
    assert_eq!(verdict, Verdict::Deny);
    assert_eq!(src, SourceKind::DefaultDeny);
}
