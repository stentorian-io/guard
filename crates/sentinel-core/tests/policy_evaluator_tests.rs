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
fn blocker_01_regression_libc_hot_path_contract() {
    // BLOCKER-01 (Phase 2 review): the libc hot path
    // (`replace_libc.rs::decide_for_sockaddr`) now delegates to
    // `evaluate_policy`. This test pins the contract for the exact inputs the
    // libc path passes:
    //
    //   1. Cache-hit / hostname-known: host=bytes, ip=Some(rendered),
    //      resolved=true → tier-walk fires. Cloud-metadata host wins.
    //   2. Cache-miss / connect-by-IP: host=b"", ip=Some(rendered),
    //      resolved=false → raw-IP cache-miss-deny fires unless loopback or
    //      cloud-metadata short-circuits first.
    //
    // The previous Phase 1 `match_hostname_compat` walker did NOT enforce
    // these hard rules — a `.sentinel.toml` ProjectAllow for IMDS would have
    // allowed AWS/Azure/GCP cloud-metadata exfil. Closing that gap is the
    // single most important behaviour change of the Phase 2 review fix pass.

    // Case 1: cache-hit on cloud-metadata host with a project allow override —
    // the hard rule MUST win even though host+ip+entries+resolved matches a
    // would-be allow.
    let allow_imds = [entry(
        RuleKind::Allow,
        RuleTier::ProjectAllow,
        MatchType::Ip,
        "169.254.169.254",
    )];
    let (v1, src1) = evaluate_policy(
        b"169.254.169.254",
        Some(b"169.254.169.254"),
        true,
        &allow_imds,
    );
    assert_eq!(v1, Verdict::Deny, "cloud-metadata hard rule must win even with ProjectAllow override");
    assert_eq!(src1, SourceKind::HardRule("cloud-metadata"));

    // Case 2: cache-miss / numeric-IP connect with no prior getaddrinfo →
    // raw-IP cache-miss-deny fires. The libc hot path passes host=b"" and
    // resolved_via_getaddrinfo=false in this state.
    let (v2, src2) = evaluate_policy(b"", Some(b"203.0.113.5"), false, &[]);
    assert_eq!(v2, Verdict::Deny);
    assert_eq!(src2, SourceKind::HardRule("raw-ip-cache-miss"));

    // Case 3: cache-miss connect to IMDS by raw IP with NO entries — both
    // raw-IP cache-miss-deny AND cloud-metadata hard rules apply; cloud
    // metadata is checked first inside the evaluator (Tier 0b before 0c).
    let (v3, src3) = evaluate_policy(b"", Some(b"169.254.169.254"), false, &[]);
    assert_eq!(v3, Verdict::Deny);
    assert_eq!(src3, SourceKind::HardRule("cloud-metadata"));

    // Case 4: cache-miss connect to a loopback IP — loopback hard rule wins
    // over cache-miss-deny (Tier 0a before 0c). The libc path's previous
    // `node_connect_to_loopback_is_allowed` plan-02-07 fix must not regress.
    let (v4, src4) = evaluate_policy(b"", Some(b"127.0.0.1"), false, &[]);
    assert_eq!(v4, Verdict::Allow);
    assert_eq!(src4, SourceKind::HardRule("loopback"));
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
