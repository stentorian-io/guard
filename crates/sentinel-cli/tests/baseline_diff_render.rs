use sentinel_ipc::ProposedRule;

#[test]
fn append_rules_produces_diffable_output() {
    let existing = "version = 1\n";
    let proposed: Vec<(&str, &str, &str, &str)> = vec![
        ("allow", "exact", "foo.s3.amazonaws.com", "baseline: 2026-05-08"),
        ("allow", "suffix", ".cloudfront.net", "baseline: 2026-05-08"),
    ];
    let new_content =
        sentinel_core::policy_file_writer::append_rules(existing, &proposed).expect("append");
    assert!(new_content.contains("foo.s3.amazonaws.com"));
    assert!(new_content.contains(".cloudfront.net"));
    let diff = similar::TextDiff::from_lines(existing, &new_content);
    let unified = diff.unified_diff().to_string();
    assert!(
        unified.contains("+pattern = \"foo.s3.amazonaws.com\""),
        "diff includes added rule"
    );
}

#[test]
fn empty_proposed_returns_unchanged_content() {
    let existing = "version = 1\n";
    let proposed: Vec<(&str, &str, &str, &str)> = vec![];
    let new_content =
        sentinel_core::policy_file_writer::append_rules(existing, &proposed).expect("append");
    assert_eq!(new_content.trim(), existing.trim());
}

#[test]
fn proposed_rule_shape_round_trip() {
    let p = ProposedRule {
        match_type: "exact".into(),
        pattern: "h.example.com".into(),
        reason: "baseline: 2026-05-08".into(),
    };
    let mut bytes = Vec::new();
    ciborium::into_writer(&p, &mut bytes).unwrap();
    let decoded: ProposedRule = ciborium::from_reader(bytes.as_slice()).unwrap();
    assert_eq!(decoded, p);
}
