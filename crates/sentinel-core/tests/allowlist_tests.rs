use sentinel_core::{AllowlistEntry, Verdict, match_hostname};

fn entries() -> Vec<AllowlistEntry> {
    vec![
        AllowlistEntry::Exact("localhost".into()),
        AllowlistEntry::Exact("registry.npmjs.org".into()),
        AllowlistEntry::Suffix(".example.com".into()),
        AllowlistEntry::Ip("127.0.0.1".into()),
    ]
}

#[test]
fn exact_match_allows() {
    assert_eq!(match_hostname(&entries(), b"localhost"), Verdict::Allow);
    assert_eq!(match_hostname(&entries(), b"registry.npmjs.org"), Verdict::Allow);
}

#[test]
fn ip_match_allows_only_exact() {
    assert_eq!(match_hostname(&entries(), b"127.0.0.1"), Verdict::Allow);
    assert_eq!(match_hostname(&entries(), b"127.0.0.10"), Verdict::Deny);
}

#[test]
fn suffix_match_requires_leading_dot() {
    assert_eq!(match_hostname(&entries(), b"foo.example.com"), Verdict::Allow);
    assert_eq!(match_hostname(&entries(), b"a.b.example.com"), Verdict::Allow);
    // The dot must match LITERALLY — "notexample.com" does NOT have ".example.com" as suffix.
    assert_eq!(match_hostname(&entries(), b"notexample.com"), Verdict::Deny);
}

#[test]
fn suffix_pattern_without_leading_dot_does_not_match_substring() {
    let no_dot = vec![AllowlistEntry::Suffix("example.com".into())];
    // Must NOT match anything because pattern lacks leading '.'.
    assert_eq!(match_hostname(&no_dot, b"foo.example.com"), Verdict::Deny);
    assert_eq!(match_hostname(&no_dot, b"example.com"), Verdict::Deny);
}

#[test]
fn miss_denies() {
    assert_eq!(match_hostname(&entries(), b"evil.example.org"), Verdict::Deny);
    assert_eq!(match_hostname(&entries(), b""), Verdict::Deny);
    assert_eq!(match_hostname(&entries(), b"registry.npmjs.org.evil.com"), Verdict::Deny);
}
