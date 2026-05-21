use guard_core::{MatchType, RuleKind, RuleTier};
use guard_daemon::curated::{CuratedError, MIN_SUFFIX_LEN, load_curated, parse_yaml};

#[test]
fn loads_more_than_fifty_entries() {
    let entries = load_curated().expect("load_curated parses embedded yaml");
    assert!(
        entries.len() > 50,
        "curated yaml should contain > 50 entries (npm/pypi/crates/ruby/go/hex/composer/maven/nuget + abuse-patterns + DoH); got {}",
        entries.len()
    );
}

#[test]
fn includes_required_ecosystems() {
    let entries = load_curated().expect("load");
    let patterns: Vec<&str> = entries.iter().map(|e| e.pattern.as_str()).collect();

    // ALLOW-01..04 ecosystem registries
    assert!(patterns.contains(&"registry.npmjs.org"), "ALLOW-01 npm");
    assert!(patterns.contains(&"pypi.org"), "ALLOW-02 pypi");
    assert!(patterns.contains(&"crates.io"), "ALLOW-03 crates.io");
    assert!(patterns.contains(&"rubygems.org"), "ALLOW-04 ruby");
    assert!(patterns.contains(&"proxy.golang.org"), "ALLOW-04 go");
    assert!(patterns.contains(&"hex.pm"), "ALLOW-04 elixir");
    assert!(patterns.contains(&"packagist.org"), "ALLOW-04 php");
    assert!(patterns.contains(&"repo1.maven.org"), "ALLOW-04 maven");
    assert!(patterns.contains(&"api.nuget.org"), "ALLOW-04 nuget");

    // ALLOW-06 abuse patterns
    assert!(
        patterns.contains(&".workers.dev"),
        "ALLOW-06 cloudflare workers"
    );
    assert!(
        patterns.contains(&".pages.dev"),
        "ALLOW-06 cloudflare pages"
    );
    assert!(patterns.contains(&"webhook.site"), "ALLOW-06 webhook.site");
    assert!(patterns.contains(&"discord.com"), "ALLOW-06 discord");
    assert!(patterns.contains(&"api.telegram.org"), "ALLOW-06 telegram");

    // ALLOW-07 DoH/DoT
    assert!(patterns.contains(&"1.1.1.1"), "ALLOW-07 cloudflare DoH");
    assert!(patterns.contains(&"8.8.8.8"), "ALLOW-07 google DoH");
    assert!(patterns.contains(&"9.9.9.9"), "ALLOW-07 quad9 DoH");
}

#[test]
fn allow_entries_get_curated_allow_tier() {
    let entries = load_curated().expect("load");
    for e in &entries {
        if matches!(e.kind, RuleKind::Allow) {
            assert!(
                matches!(e.tier, RuleTier::CuratedAllow),
                "allow entry must be CuratedAllow tier: {:?}",
                e
            );
        }
    }
}

#[test]
fn deny_entries_get_builtin_deny_tier() {
    let entries = load_curated().expect("load");
    for e in &entries {
        if matches!(e.kind, RuleKind::Deny) {
            assert!(
                matches!(e.tier, RuleTier::BuiltinDeny),
                "deny entry must be BuiltinDeny tier: {:?}",
                e
            );
        }
    }
}

#[test]
fn every_entry_has_nonempty_reason() {
    let entries = load_curated().expect("load");
    for e in &entries {
        assert!(!e.reason.trim().is_empty(), "empty reason on {:?}", e);
    }
}

#[test]
#[allow(non_snake_case)]
fn cloud_metadata_is_NOT_in_yaml_only_in_code() {
    let entries = load_curated().expect("load");
    let patterns: Vec<&str> = entries.iter().map(|e| e.pattern.as_str()).collect();
    assert!(
        !patterns.contains(&"169.254.169.254"),
        "169.254.169.254 must NOT be in YAML — it is a HARD RULE in policy.rs (D-25b)"
    );
}

#[test]
fn parse_yaml_rejects_overbroad_suffix() {
    let bad = r#"
entries:
  - kind: deny
    match: suffix
    pattern: .x
    reason: too short
"#;
    let res = parse_yaml(bad);
    match res {
        Err(CuratedError::InvalidPattern { reason, .. }) => {
            assert!(
                reason.contains("too short"),
                "expected 'too short' diagnostic, got: {reason}"
            );
        }
        other => panic!("expected InvalidPattern, got {other:?}"),
    }
}

/// WARNING (v0.2 review): single-TLD suffixes like `.com` (4 bytes)
/// are catastrophically over-broad — `.com` matches every `.com` host on
/// the internet. The previous `MIN_SUFFIX_LEN = 4` accepted these. The
/// fix raised the limit to 6 so all the canonical mistakes are rejected.
#[test]
fn parse_yaml_rejects_top_level_tld_suffix() {
    for bad_tld in [".com", ".org", ".net", ".dev", ".app", ".io"] {
        let yaml = format!(
            "entries:\n  - kind: deny\n    match: suffix\n    pattern: {}\n    reason: too broad\n",
            bad_tld
        );
        let res = parse_yaml(&yaml);
        assert!(
            matches!(res, Err(CuratedError::InvalidPattern { .. })),
            "WARNING: pattern {} must be rejected as too short; got {:?}",
            bad_tld,
            res
        );
    }
    // Sanity check: legitimate suffixes >= 6 bytes still pass.
    let ok_yaml = "entries:\n  - kind: allow\n    match: suffix\n    pattern: .co.uk\n    reason: legit ccTLD\n";
    assert!(
        parse_yaml(ok_yaml).is_ok(),
        ".co.uk (6 bytes) must be accepted"
    );
}

#[test]
fn parse_yaml_rejects_suffix_without_leading_dot() {
    let bad = r#"
entries:
  - kind: deny
    match: suffix
    pattern: workers.dev
    reason: missing leading dot
"#;
    let res = parse_yaml(bad);
    match res {
        Err(CuratedError::InvalidPattern { reason, .. }) => {
            assert!(reason.contains("must start with '.'"), "got: {reason}");
        }
        other => panic!("expected InvalidPattern, got {other:?}"),
    }
}

#[test]
fn parse_yaml_rejects_empty_reason() {
    let bad = r#"
entries:
  - kind: allow
    match: exact
    pattern: x.com
    reason: ""
"#;
    let res = parse_yaml(bad);
    match res {
        Err(CuratedError::InvalidPattern { reason, .. }) => {
            assert!(reason.contains("reason field is empty"), "got: {reason}");
        }
        other => panic!("expected InvalidPattern, got {other:?}"),
    }
}

#[test]
fn parse_yaml_rejects_malformed() {
    let bad = "not yaml at all { ::: ";
    match parse_yaml(bad) {
        Err(CuratedError::Parse(_)) => {}
        other => panic!("expected Parse error, got {other:?}"),
    }
}

#[test]
fn min_suffix_len_const_is_6() {
    // WARNING: raised from 4 to 6 to reject single-TLD suffixes like
    // ".com" / ".org" / ".net" / ".dev" / ".app" / ".io".
    assert_eq!(MIN_SUFFIX_LEN, 6);
}

// Suppress dev-dep usage warning for MatchType (used implicitly via load_curated entries).
#[allow(dead_code)]
fn _force_match_type_use() -> MatchType {
    MatchType::Exact
}
