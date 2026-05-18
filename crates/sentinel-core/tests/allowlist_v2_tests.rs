use sentinel_core::{AllowlistEntry, MatchType, RuleKind, RuleTier, Verdict, evaluate_rule};

fn allow(pattern: &str, mt: MatchType) -> AllowlistEntry {
    AllowlistEntry {
        kind: RuleKind::Allow,
        tier: RuleTier::CuratedAllow,
        match_type: mt,
        pattern: pattern.into(),
        reason: "test".into(),
    }
}

fn deny(pattern: &str, mt: MatchType, tier: RuleTier) -> AllowlistEntry {
    AllowlistEntry {
        kind: RuleKind::Deny,
        tier,
        match_type: mt,
        pattern: pattern.into(),
        reason: "test".into(),
    }
}

#[test]
fn exact_matches_only_full_host() {
    let e = allow("registry.npmjs.org", MatchType::Exact);
    assert!(e.matches(b"registry.npmjs.org"));
    assert!(!e.matches(b"x.registry.npmjs.org"));
    assert!(!e.matches(b"npmjs.org"));
}

#[test]
fn suffix_requires_leading_dot_and_blocks_substring_widening() {
    let e = allow(".workers.dev", MatchType::Suffix);
    assert!(e.matches(b"foo.workers.dev"));
    assert!(e.matches(b"a.b.workers.dev"));
    assert!(!e.matches(b"workers.dev")); // no leading dot in host
    assert!(!e.matches(b"notworkers.dev")); // substring trap

    let bad = allow("workers.dev", MatchType::Suffix);
    assert!(
        !bad.matches(b"foo.workers.dev"),
        "pattern lacking leading dot must be no-match"
    );
    assert!(!bad.matches(b"workers.dev"));
}

#[test]
fn evaluate_rule_returns_kind_on_match_none_on_miss() {
    let a = allow("example.com", MatchType::Exact);
    assert_eq!(evaluate_rule(&a, b"example.com"), Some(Verdict::Allow));
    assert_eq!(evaluate_rule(&a, b"other.com"), None);

    let d = deny(".workers.dev", MatchType::Suffix, RuleTier::BuiltinDeny);
    assert_eq!(evaluate_rule(&d, b"x.workers.dev"), Some(Verdict::Deny));
    assert_eq!(evaluate_rule(&d, b"workers.dev"), None);
}

#[test]
fn tier_ordering_implements_precedence() {
    assert!(RuleTier::BuiltinDeny < RuleTier::CuratedAllow);
    assert!(RuleTier::CuratedAllow < RuleTier::UserDeny);
    assert!(RuleTier::UserDeny < RuleTier::FeedDeny);
    assert!(RuleTier::FeedDeny < RuleTier::UserAllow);
}

#[test]
fn allowlist_entry_ciborium_roundtrip() {
    let e = AllowlistEntry {
        kind: RuleKind::Deny,
        tier: RuleTier::BuiltinDeny,
        match_type: MatchType::Suffix,
        pattern: ".pages.dev".into(),
        reason: "Cloudflare Pages C2".into(),
    };
    let mut buf = Vec::new();
    ciborium::ser::into_writer(&e, &mut buf).unwrap();
    let back: AllowlistEntry = ciborium::de::from_reader(buf.as_slice()).unwrap();
    assert_eq!(e, back);
}

#[test]
fn rule_tier_serde_roundtrips_each_variant() {
    for &t in &[
        RuleTier::BuiltinDeny,
        RuleTier::CuratedAllow,
        RuleTier::UserDeny,
        RuleTier::FeedDeny,
        RuleTier::UserAllow,
    ] {
        let mut buf = Vec::new();
        ciborium::ser::into_writer(&t, &mut buf).unwrap();
        let back: RuleTier = ciborium::de::from_reader(buf.as_slice()).unwrap();
        assert_eq!(t, back);
    }
}
