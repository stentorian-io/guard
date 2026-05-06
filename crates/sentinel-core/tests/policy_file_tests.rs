use sentinel_core::policy_file::{parse, PolicyFileError};
use sentinel_core::{MatchType, RuleKind};

#[test]
fn parses_minimal_valid_toml() {
    let content = r#"
version = 1

[[rules]]
kind = "allow"
match = "exact"
pattern = "internal-registry.acme.com"
reason = "corp-internal mirror"
"#;
    let t = parse(content).expect("parse");
    assert_eq!(t.version, 1);
    assert_eq!(t.rules.len(), 1);
    let r = &t.rules[0];
    assert!(matches!(r.kind, RuleKind::Allow));
    assert!(matches!(r.match_type, MatchType::Exact));
    assert_eq!(r.pattern, "internal-registry.acme.com");
    assert_eq!(r.reason, "corp-internal mirror");
}

#[test]
fn rejects_unsupported_version() {
    let content = "version = 2\n";
    match parse(content) {
        Err(PolicyFileError::UnsupportedVersion(2)) => {}
        other => panic!("expected UnsupportedVersion(2), got {other:?}"),
    }
}

#[test]
fn missing_reason_field_errors_at_parse() {
    let content = r#"
version = 1
[[rules]]
kind = "allow"
match = "exact"
pattern = "x.com"
"#;
    match parse(content) {
        Err(PolicyFileError::ParseError(msg)) => {
            assert!(
                msg.contains("reason"),
                "error message must name the missing field; got: {msg}"
            );
        }
        other => panic!("expected ParseError mentioning `reason`, got {other:?}"),
    }
}

#[test]
fn empty_rules_array_is_valid() {
    let content = "version = 1\n";
    let t = parse(content).expect("parse");
    assert_eq!(t.rules.len(), 0);
}

#[test]
fn deny_suffix_parses() {
    let content = r#"
version = 1
[[rules]]
kind = "deny"
match = "suffix"
pattern = ".staging-cdn.acme.com"
reason = "staging traffic should never come from this repo"
"#;
    let t = parse(content).expect("parse");
    let r = &t.rules[0];
    assert!(matches!(r.kind, RuleKind::Deny));
    assert!(matches!(r.match_type, MatchType::Suffix));
}

#[test]
fn malformed_toml_returns_parse_error() {
    let content = "not toml at all { ::: ";
    match parse(content) {
        Err(PolicyFileError::ParseError(_)) => {}
        other => panic!("expected ParseError, got {other:?}"),
    }
}
