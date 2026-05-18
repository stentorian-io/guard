use sentinel_daemon::handlers::resolve::{handle_resolve, load_run_entries};
use sentinel_core::allowlist::{AllowlistEntry, MatchType, RuleKind, RuleTier};
use sentinel_core::policy::evaluate_policy;
use sentinel_core::Snapshot;
use sentinel_ipc::ResolveReply;

#[test]
fn resolve_localhost_returns_addresses() {
    let r = handle_resolve("localhost", 80);
    match r {
        ResolveReply::Addresses { addrs, .. } => {
            assert!(
                !addrs.is_empty(),
                "localhost should resolve to at least one address"
            );
            // Second byte is family (AF_INET=2 or AF_INET6=30 on Darwin).
            for a in &addrs {
                let family = a[1];
                assert!(
                    family == libc::AF_INET as u8 || family == libc::AF_INET6 as u8,
                    "unexpected family {family}"
                );
            }
        }
        other => panic!("expected Addresses; got {other:?}"),
    }
}

#[test]
fn resolve_invalid_host_returns_err() {
    let r = handle_resolve("this-host-does-not-exist-12345.invalid", 80);
    assert!(matches!(r, ResolveReply::Err { .. }));
}

#[test]
fn load_run_entries_from_snapshot() {
    let snap = Snapshot {
        schema_version: 2,
        generated_at_unix_ms: 0,
        entries: vec![AllowlistEntry {
            kind: RuleKind::Allow,
            tier: RuleTier::CuratedAllow,
            match_type: MatchType::Suffix,
            pattern: ".npmjs.org".into(),
            reason: "npm registry".into(),
        }],
        run_uuid: Some("test-uuid".into()),
    };
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("test.cbor");
    std::fs::write(&path, snap.encode().unwrap()).unwrap();

    let entries = load_run_entries(&path).expect("should decode");
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].pattern, ".npmjs.org");
}

#[test]
fn load_run_entries_missing_file_returns_none() {
    assert!(load_run_entries(std::path::Path::new("/nonexistent/snapshot.cbor")).is_none());
}

#[test]
fn policy_gate_allows_matching_host() {
    let entries = vec![AllowlistEntry {
        kind: RuleKind::Allow,
        tier: RuleTier::CuratedAllow,
        match_type: MatchType::Suffix,
        pattern: ".npmjs.org".into(),
        reason: "npm registry".into(),
    }];
    let (verdict, _source) = evaluate_policy(
        b"registry.npmjs.org",
        None,
        false,
        &entries,
    );
    assert_eq!(verdict, sentinel_core::Verdict::Allow);
}

#[test]
fn policy_gate_denies_unknown_host() {
    let entries = vec![AllowlistEntry {
        kind: RuleKind::Allow,
        tier: RuleTier::CuratedAllow,
        match_type: MatchType::Suffix,
        pattern: ".npmjs.org".into(),
        reason: "npm registry".into(),
    }];
    let (verdict, _source) = evaluate_policy(
        b"evil.attacker.com",
        None,
        false,
        &entries,
    );
    assert_eq!(verdict, sentinel_core::Verdict::Deny);
}

#[test]
fn policy_gate_allows_loopback_regardless() {
    let entries = vec![];
    let (verdict, _) = evaluate_policy(b"localhost", None, false, &entries);
    assert_eq!(verdict, sentinel_core::Verdict::Allow);
}
