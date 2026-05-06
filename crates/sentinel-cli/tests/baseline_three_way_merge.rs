//! Phase 3 plan 03-13 BLOCKER #2 — D-60 3-way merge dedup test.

use sentinel_cli::baseline::extract_existing_rule_keys;
use sentinel_ipc::ProposedRule;

#[test]
fn merged_dedup_collapses_overlap() {
    let existing = r#"version = 1

[[rules]]
kind = "allow"
match = "exact"
pattern = "registry.npmjs.org"
reason = "existing"

[[rules]]
kind = "allow"
match = "suffix"
pattern = ".cloudfront.net"
reason = "existing"

[[rules]]
kind = "allow"
match = "exact"
pattern = "github.com"
reason = "existing"
"#;
    let proposed = vec![
        ProposedRule {
            // NEW
            match_type: "exact".into(),
            pattern: "foo.s3.amazonaws.com".into(),
            reason: "baseline: 2026-05-08".into(),
        },
        ProposedRule {
            // NEW
            match_type: "suffix".into(),
            pattern: ".pypi.org".into(),
            reason: "baseline: 2026-05-08".into(),
        },
        ProposedRule {
            // OVERLAP — same (match=exact, pattern=registry.npmjs.org) as existing
            match_type: "exact".into(),
            pattern: "registry.npmjs.org".into(),
            reason: "baseline: 2026-05-08".into(),
        },
    ];

    let existing_keys = extract_existing_rule_keys(existing);
    assert_eq!(existing_keys.len(), 3);
    assert!(existing_keys.contains(&("exact".into(), "registry.npmjs.org".into())));

    // Build "merged": existing + only proposed rules whose key is NOT in existing.
    let to_append: Vec<(&str, &str, &str, &str)> = proposed
        .iter()
        .filter(|r| !existing_keys.contains(&(r.match_type.clone(), r.pattern.clone())))
        .map(|r| {
            (
                "allow",
                r.match_type.as_str(),
                r.pattern.as_str(),
                r.reason.as_str(),
            )
        })
        .collect();
    assert_eq!(to_append.len(), 2, "overlap rule must be filtered out");

    let merged =
        sentinel_core::policy_file_writer::append_rules(existing, &to_append).expect("append");
    let merged_keys = extract_existing_rule_keys(&merged);
    assert_eq!(
        merged_keys.len(),
        5,
        "merged has 3 existing + 2 new = 5 unique rules"
    );
    assert!(merged_keys.contains(&("exact".into(), "foo.s3.amazonaws.com".into())));
    assert!(merged_keys.contains(&("suffix".into(), ".pypi.org".into())));
    assert!(merged_keys.contains(&("exact".into(), "registry.npmjs.org".into())));
    assert!(merged_keys.contains(&("suffix".into(), ".cloudfront.net".into())));
    assert!(merged_keys.contains(&("exact".into(), "github.com".into())));

    // Build "proposed-only": stub + all 3 proposed.
    let proposed_rules: Vec<(&str, &str, &str, &str)> = proposed
        .iter()
        .map(|r| {
            (
                "allow",
                r.match_type.as_str(),
                r.pattern.as_str(),
                r.reason.as_str(),
            )
        })
        .collect();
    let proposed_only =
        sentinel_core::policy_file_writer::append_rules("version = 1\n", &proposed_rules)
            .expect("append");
    let proposed_keys = extract_existing_rule_keys(&proposed_only);
    assert_eq!(proposed_keys.len(), 3);
    assert!(!proposed_keys.contains(&("suffix".into(), ".cloudfront.net".into())));
    assert!(!proposed_keys.contains(&("exact".into(), "github.com".into())));
}

#[test]
fn extract_keys_handles_no_rules() {
    let stub = "version = 1\n";
    let keys = extract_existing_rule_keys(stub);
    assert!(keys.is_empty());
}
