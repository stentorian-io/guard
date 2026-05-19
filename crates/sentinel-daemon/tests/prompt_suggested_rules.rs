use sentinel_daemon::prompt::generate_suggested_rules;

#[test]
fn s3_amazonaws_shared_cdn_three_suggestions() {
    let s = generate_suggested_rules("foo.s3.amazonaws.com");
    assert_eq!(s.len(), 3, "got: {s:?}");
    assert_eq!(s[0].pattern, "foo.s3.amazonaws.com"); assert_eq!(s[0].match_type, "exact");
    assert_eq!(s[1].pattern, "s3.amazonaws.com");    assert_eq!(s[1].match_type, "exact");
    assert_eq!(s[2].pattern, ".s3.amazonaws.com");   assert_eq!(s[2].match_type, "suffix");
}

#[test]
fn api_example_com_two_suggestions() {
    let s = generate_suggested_rules("api.example.com");
    assert_eq!(s.len(), 2);
    assert_eq!(s[0].pattern, "api.example.com");
    assert_eq!(s[1].pattern, ".example.com");
    assert_eq!(s[1].match_type, "suffix");
}

#[test]
fn example_com_only_exact() {
    let s = generate_suggested_rules("example.com");
    assert_eq!(s.len(), 1);
    assert_eq!(s[0].pattern, "example.com");
    assert_eq!(s[0].match_type, "exact");
}

#[test]
fn ipv4_only_exact() {
    let s = generate_suggested_rules("1.2.3.4");
    assert_eq!(s.len(), 1);
    assert_eq!(s[0].pattern, "1.2.3.4");
}

#[test]
fn deep_subdomain_exact_plus_suffix_on_parent() {
    let s = generate_suggested_rules("a.b.c.d.example.com");
    assert_eq!(s.len(), 2);
    assert_eq!(s[0].pattern, "a.b.c.d.example.com");
    assert_eq!(s[1].pattern, ".b.c.d.example.com");
    assert_eq!(s[1].match_type, "suffix");
}

#[test]
fn workers_dev_not_in_shared_cdn_list() {
    // workers.dev is on the v0.2 ALLOW-06 denylist; should NOT generate the
    // shared-CDN exact-SLD suggestion (only exact host + suffix).
    let s = generate_suggested_rules("foo.workers.dev");
    assert_eq!(s.len(), 2);
    assert_eq!(s[0].pattern, "foo.workers.dev");
    assert_eq!(s[1].pattern, ".workers.dev");
    // Crucially, no `s[1].pattern == "workers.dev"` exact-SLD entry.
    assert!(!s.iter().any(|r| r.pattern == "workers.dev" && r.match_type == "exact"));
}
