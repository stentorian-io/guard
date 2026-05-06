use sentinel_core::{
    AllowlistEntry, MatchType, RuleKind, RuleTier, SourceKind, Verdict, evaluate_policy,
    is_cloud_metadata_host, is_cloud_metadata_ip, is_loopback_host, is_loopback_ip,
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

// --- Hard rule predicates -----------------------------------------------

#[test]
fn hard_rule_loopback_predicates() {
    assert!(is_loopback_host(b"localhost"));
    assert!(is_loopback_host(b"localhost6"));
    assert!(!is_loopback_host(b"localhostx"));
    assert!(is_loopback_ip(b"127.0.0.1"));
    assert!(is_loopback_ip(b"127.255.255.255"));
    assert!(is_loopback_ip(b"::1"));
    assert!(!is_loopback_ip(b"10.0.0.1"));
}

#[test]
fn hard_rule_cloud_metadata_predicates() {
    assert!(is_cloud_metadata_host(b"169.254.169.254"));
    assert!(is_cloud_metadata_host(b"fe80::a9fe:a9fe"));
    assert!(!is_cloud_metadata_host(b"169.254.169.255"));
    assert!(is_cloud_metadata_ip(b"169.254.169.254"));
}

// --- Hard rules in evaluate_policy --------------------------------------

#[test]
fn evaluate_loopback_host_allows() {
    let (v, src) = evaluate_policy(b"localhost", None, false, &[]);
    assert_eq!(v, Verdict::Allow);
    assert_eq!(src, SourceKind::HardRule("loopback"));
}

#[test]
fn evaluate_loopback_ip_allows() {
    let (v, src) = evaluate_policy(b"", Some(b"127.0.0.1"), false, &[]);
    assert_eq!(v, Verdict::Allow);
    assert_eq!(src, SourceKind::HardRule("loopback"));
}

#[test]
fn evaluate_cloud_metadata_denies_unconditionally() {
    // Entries trying to allow 169.254.169.254 must NOT override the hard rule.
    let entries = [entry(
        RuleKind::Allow,
        RuleTier::ProjectAllow,
        MatchType::Exact,
        "169.254.169.254",
    )];
    let (v, src) = evaluate_policy(b"169.254.169.254", None, true, &entries);
    assert_eq!(v, Verdict::Deny);
    assert_eq!(src, SourceKind::HardRule("cloud-metadata"));
}

#[test]
fn evaluate_raw_ip_cache_miss_denies_allow_08() {
    // No prior getaddrinfo → deny.
    let (v, src) = evaluate_policy(b"", Some(b"203.0.113.5"), false, &[]);
    assert_eq!(v, Verdict::Deny);
    assert_eq!(src, SourceKind::HardRule("raw-ip-cache-miss"));
}

#[test]
fn evaluate_resolved_ip_falls_through_to_default_deny_when_no_match() {
    let (v, src) = evaluate_policy(b"unknown.example", Some(b"203.0.113.5"), true, &[]);
    assert_eq!(v, Verdict::Deny);
    assert_eq!(src, SourceKind::DefaultDeny);
}

// --- Tier walk ----------------------------------------------------------

#[test]
fn curated_allow_returns_curated_source() {
    let entries = [entry(
        RuleKind::Allow,
        RuleTier::CuratedAllow,
        MatchType::Exact,
        "registry.npmjs.org",
    )];
    let (v, src) = evaluate_policy(b"registry.npmjs.org", None, true, &entries);
    assert_eq!(v, Verdict::Allow);
    assert_eq!(src, SourceKind::CuratedAllow);
}

#[test]
fn builtin_deny_blocks_workers_dev() {
    let entries = [entry(
        RuleKind::Deny,
        RuleTier::BuiltinDeny,
        MatchType::Suffix,
        ".workers.dev",
    )];
    let (v, src) = evaluate_policy(b"foo.workers.dev", None, true, &entries);
    assert_eq!(v, Verdict::Deny);
    assert_eq!(src, SourceKind::BuiltinDeny);
}

// --- POL-06 regression -----------------------------------------------

#[test]
fn pol_06_curated_allow_beats_feed_deny() {
    // Entries pre-sorted by tier — curated_allow at index 0, feed_deny at 1.
    let entries = [
        entry(
            RuleKind::Allow,
            RuleTier::CuratedAllow,
            MatchType::Exact,
            "registry.npmjs.org",
        ),
        entry(
            RuleKind::Deny,
            RuleTier::FeedDeny,
            MatchType::Exact,
            "registry.npmjs.org",
        ),
    ];
    let (v, src) = evaluate_policy(b"registry.npmjs.org", None, true, &entries);
    assert_eq!(v, Verdict::Allow, "POL-06: curated allow must beat feed deny");
    assert_eq!(src, SourceKind::CuratedAllow);
}

// --- D-26 regression --------------------------------------------------

#[test]
fn sentinel_toml_cannot_override_builtin_deny() {
    // BuiltinDeny at tier 0; ProjectAllow at tier 5. Tier 0 fires first.
    let entries = [
        entry(
            RuleKind::Deny,
            RuleTier::BuiltinDeny,
            MatchType::Suffix,
            ".workers.dev",
        ),
        entry(
            RuleKind::Allow,
            RuleTier::ProjectAllow,
            MatchType::Suffix,
            ".workers.dev",
        ),
    ];
    let (v, src) = evaluate_policy(b"my-deploy.workers.dev", None, true, &entries);
    assert_eq!(v, Verdict::Deny);
    assert_eq!(src, SourceKind::BuiltinDeny);
}

// --- ProjectDeny / UserAllow tiers --------------------------------------

#[test]
fn project_deny_fires_before_user_allow() {
    let entries = [
        entry(
            RuleKind::Deny,
            RuleTier::ProjectDeny,
            MatchType::Exact,
            "x.com",
        ),
        entry(
            RuleKind::Allow,
            RuleTier::UserAllow,
            MatchType::Exact,
            "x.com",
        ),
    ];
    let (v, src) = evaluate_policy(b"x.com", None, true, &entries);
    assert_eq!(v, Verdict::Deny);
    assert_eq!(src, SourceKind::ProjectDeny);
}

#[test]
fn user_allow_used_when_no_higher_tier_matches() {
    let entries = [entry(
        RuleKind::Allow,
        RuleTier::UserAllow,
        MatchType::Exact,
        "x.com",
    )];
    let (v, src) = evaluate_policy(b"x.com", None, true, &entries);
    assert_eq!(v, Verdict::Allow);
    assert_eq!(src, SourceKind::UserAllow);
}
