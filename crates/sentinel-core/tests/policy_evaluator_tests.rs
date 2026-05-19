use sentinel_core::{
    AllowlistEntry, MatchType, RuleKind, RuleTier, SourceKind, Verdict, evaluate_policy,
    has_user_allow, is_cloud_metadata_host, is_cloud_metadata_ip, is_loopback_host,
    is_loopback_ip,
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

#[test]
fn warning_05_regression_cloud_metadata_ipv6_normalization() {
    // WARNING-05: IPv6 link-local IMDS has many textual representations.
    // The hard rule MUST fire on all of them.
    //
    //   1. canonical lowercase                    fe80::a9fe:a9fe
    //   2. uppercase hex                          FE80::A9FE:A9FE
    //   3. mixed case                             fe80::A9FE:A9FE
    //   4. no double-colon compression            fe80:0:0:0:0:0:a9fe:a9fe
    //   5. zone-id suffix                         fe80::a9fe:a9fe%en0
    //   6. uppercase + zone-id                    FE80::A9FE:A9FE%en0
    let cases: &[&[u8]] = &[
        b"fe80::a9fe:a9fe",
        b"FE80::A9FE:A9FE",
        b"fe80::A9FE:A9FE",
        b"fe80:0:0:0:0:0:a9fe:a9fe",
        b"fe80::a9fe:a9fe%en0",
        b"FE80::A9FE:A9FE%en0",
    ];
    for input in cases {
        assert!(
            is_cloud_metadata_host(input),
            "WARNING-05: cloud-metadata host check must accept {:?}",
            std::str::from_utf8(input).unwrap_or("<bad utf-8>")
        );
    }
    // Negative controls: link-local but NOT the IMDS magic.
    assert!(!is_cloud_metadata_host(b"fe80::a9fe:a9ff"));
    assert!(!is_cloud_metadata_host(b"fe80::1"));
    assert!(!is_cloud_metadata_host(b"::1"));
    // Junk inputs.
    assert!(!is_cloud_metadata_host(b""));
    assert!(!is_cloud_metadata_host(b"not-an-address"));
    assert!(!is_cloud_metadata_host(b"%en0"));
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
        RuleTier::UserAllow,
        MatchType::Exact,
        "169.254.169.254",
    )];
    let (v, src) = evaluate_policy(b"169.254.169.254", None, true, &entries);
    assert_eq!(v, Verdict::Deny);
    assert_eq!(src, SourceKind::HardRule("cloud-metadata"));
}

#[test]
fn blocker_01_regression_libc_hot_path_contract() {
    // BLOCKER-01 (v0.2 review): the libc hot path
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
    // The previous v0.1 `match_hostname_compat` walker did NOT enforce
    // these hard rules — a UserAllow for IMDS would have allowed
    // AWS/Azure/GCP cloud-metadata exfil. Closing that gap is the single most
    // important behaviour change of the v0.2 review fix pass.

    // Case 1: cache-hit on cloud-metadata host with a user allow override —
    // the hard rule MUST win even though host+ip+entries+resolved matches a
    // would-be allow.
    let allow_imds = [entry(
        RuleKind::Allow,
        RuleTier::UserAllow,
        MatchType::Ip,
        "169.254.169.254",
    )];
    let (v1, src1) = evaluate_policy(
        b"169.254.169.254",
        Some(b"169.254.169.254"),
        true,
        &allow_imds,
    );
    assert_eq!(v1, Verdict::Deny, "cloud-metadata hard rule must win even with UserAllow override");
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
    // `node_connect_to_loopback_is_allowed` fix must not regress.
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
fn pol_06_curated_allow_beats_confirmed_deny() {
    let entries = [
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
    let (v, src) = evaluate_policy(b"registry.npmjs.org", None, true, &entries);
    assert_eq!(v, Verdict::Allow, "POL-06: curated allow must beat feed deny");
    assert_eq!(src, SourceKind::CuratedAllow);
}

// --- D-26 regression --------------------------------------------------

#[test]
fn lower_tier_cannot_override_builtin_deny() {
    // BuiltinDeny at tier 0; UserAllow at tier 4. Tier 0 fires first.
    let entries = [
        entry(
            RuleKind::Deny,
            RuleTier::BuiltinDeny,
            MatchType::Suffix,
            ".workers.dev",
        ),
        entry(
            RuleKind::Allow,
            RuleTier::UserAllow,
            MatchType::Suffix,
            ".workers.dev",
        ),
    ];
    let (v, src) = evaluate_policy(b"my-deploy.workers.dev", None, true, &entries);
    assert_eq!(v, Verdict::Deny);
    assert_eq!(src, SourceKind::BuiltinDeny);
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

#[test]
fn source_kind_as_label_covers_all_variants() {
    assert_eq!(SourceKind::HardRule("loopback").as_label(), "loopback");
    assert_eq!(SourceKind::HardRule("cloud-metadata").as_label(), "cloud-metadata-blocked");
    assert_eq!(SourceKind::HardRule("raw-ip-cache-miss").as_label(), "raw-ip-no-dns");
    assert_eq!(SourceKind::HardRule("fail-closed").as_label(), "fail-closed");
    assert_eq!(SourceKind::HardRule("unknown").as_label(), "hard-rule");
    assert_eq!(SourceKind::BuiltinDeny.as_label(), "builtin-deny");
    assert_eq!(SourceKind::CuratedAllow.as_label(), "curated-allow");
    assert_eq!(SourceKind::UserDeny.as_label(), "user-deny");
    assert_eq!(SourceKind::ConfirmedDeny.as_label(), "confirmed-deny");
    assert_eq!(SourceKind::SuspectDeny.as_label(), "suspect-deny");
    assert_eq!(SourceKind::UserAllow.as_label(), "user-allow");
    assert_eq!(SourceKind::DefaultDeny.as_label(), "default-deny");
}

#[test]
fn has_user_allow_detects_overlap() {
    let entries = [
        entry(RuleKind::Deny, RuleTier::ConfirmedDeny, MatchType::Exact, "evil.com"),
        entry(RuleKind::Allow, RuleTier::UserAllow, MatchType::Exact, "evil.com"),
    ];
    assert!(has_user_allow(b"evil.com", &entries));
    assert!(!has_user_allow(b"other.com", &entries));
}

#[test]
fn confirmed_deny_overrides_user_allow() {
    let mut entries = vec![
        entry(RuleKind::Allow, RuleTier::UserAllow, MatchType::Exact, "evil.com"),
        entry(RuleKind::Deny, RuleTier::ConfirmedDeny, MatchType::Exact, "evil.com"),
    ];
    entries.sort_by_key(|e| e.tier);
    let (v, src) = evaluate_policy(b"evil.com", None, true, &entries);
    assert_eq!(v, Verdict::Deny);
    assert_eq!(src, SourceKind::ConfirmedDeny);
    assert!(has_user_allow(b"evil.com", &entries));
}
