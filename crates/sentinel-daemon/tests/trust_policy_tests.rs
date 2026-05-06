use sentinel_daemon::handlers::trust_policy::handle_trust_policy;
use sentinel_daemon::rule_store::RuleStore;
use tempfile::TempDir;

#[test]
fn trust_policy_inserts_when_hash_matches() {
    let tmp = TempDir::new().unwrap();
    let f = tmp.path().join(".sentinel.toml");
    std::fs::write(&f, "version = 1\n").unwrap();
    let actual = sentinel_daemon::policy_file::sha256_of_file(&f).unwrap();

    let rs = RuleStore::open(&tmp.path().join("sentinel.db")).unwrap();
    let path_str = f.display().to_string();
    let reply = handle_trust_policy(&path_str, &actual, &rs);
    match reply {
        sentinel_ipc::TrustPolicyReply::Ok { .. } => {}
        sentinel_ipc::TrustPolicyReply::Err { message, .. } => {
            panic!("expected Ok; got Err: {message}");
        }
    }
    assert!(rs.is_trusted(&path_str, &actual).unwrap());
}

#[test]
fn trust_policy_rejects_on_hash_mismatch() {
    let tmp = TempDir::new().unwrap();
    let f = tmp.path().join(".sentinel.toml");
    std::fs::write(&f, "version = 1\n").unwrap();
    let rs = RuleStore::open(&tmp.path().join("sentinel.db")).unwrap();
    let claimed_wrong = "0".repeat(64);
    let reply = handle_trust_policy(&f.display().to_string(), &claimed_wrong, &rs);
    match reply {
        sentinel_ipc::TrustPolicyReply::Err { message, .. } => {
            assert!(
                message.contains("hash mismatch"),
                "expected hash mismatch error; got {message}"
            );
        }
        other => panic!("expected Err; got {other:?}"),
    }
    // RuleStore should not have been touched.
    assert!(!rs
        .is_trusted(&f.display().to_string(), &claimed_wrong)
        .unwrap());
}

#[test]
fn trust_policy_rejects_missing_file() {
    let tmp = TempDir::new().unwrap();
    let rs = RuleStore::open(&tmp.path().join("sentinel.db")).unwrap();
    let reply = handle_trust_policy(
        &tmp.path().join("does-not-exist").display().to_string(),
        &"a".repeat(64),
        &rs,
    );
    assert!(matches!(reply, sentinel_ipc::TrustPolicyReply::Err { .. }));
}
