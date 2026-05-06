use sentinel_daemon::handlers::trust_policy::handle_trust_policy;
use sentinel_daemon::rule_store::RuleStore;
use tempfile::TempDir;

/// macOS resolves `/var/folders/...` (the `tempfile::TempDir` parent) through
/// a symlink to `/private/var/folders/...`. The BLOCKER-03 canonicalization
/// gate rejects non-canonical paths, so tests must canonicalize before
/// sending. Use this helper in every TrustPolicy test.
fn canonical_str(p: &std::path::Path) -> String {
    p.canonicalize()
        .expect("canonicalize")
        .display()
        .to_string()
}

#[test]
fn trust_policy_inserts_when_hash_matches() {
    let tmp = TempDir::new().unwrap();
    let f = tmp.path().join(".sentinel.toml");
    std::fs::write(&f, "version = 1\n").unwrap();
    let actual = sentinel_daemon::policy_file::sha256_of_file(&f).unwrap();

    let rs = RuleStore::open(&tmp.path().join("sentinel.db")).unwrap();
    let path_str = canonical_str(&f);
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
    let reply = handle_trust_policy(&canonical_str(&f), &claimed_wrong, &rs);
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
        .is_trusted(&canonical_str(&f), &claimed_wrong)
        .unwrap());
}

#[test]
fn trust_policy_rejects_missing_file() {
    let tmp = TempDir::new().unwrap();
    let rs = RuleStore::open(&tmp.path().join("sentinel.db")).unwrap();
    // Cannot canonicalize a non-existent path; let the handler reject it
    // (canonicalize fails first with ENOENT, surfaced as a `canonicalize: …`
    // error message).
    let reply = handle_trust_policy(
        &tmp.path().join("does-not-exist").display().to_string(),
        &"a".repeat(64),
        &rs,
    );
    assert!(matches!(reply, sentinel_ipc::TrustPolicyReply::Err { .. }));
}

/// BLOCKER-03 regression: a non-canonical path (with `/./` or symlink
/// component) MUST be rejected — even if the file at that path exists and
/// the hash matches. The wire input must be the canonical absolute path,
/// matching what `find_sentinel_toml` produces during PrepareSnapshot.
#[test]
fn trust_policy_rejects_non_canonical_path() {
    let tmp = TempDir::new().unwrap();
    let f = tmp.path().join(".sentinel.toml");
    std::fs::write(&f, "version = 1\n").unwrap();
    let actual = sentinel_daemon::policy_file::sha256_of_file(&f).unwrap();

    let rs = RuleStore::open(&tmp.path().join("sentinel.db")).unwrap();
    // Construct a path that points to the same file but is NOT canonical:
    // insert a `/./` component into the otherwise-canonical absolute path.
    let canonical = canonical_str(&f);
    let dotted = canonical.replacen('/', "/./", 1);
    assert_ne!(canonical, dotted, "test setup: path must differ");
    let reply = handle_trust_policy(&dotted, &actual, &rs);
    match reply {
        sentinel_ipc::TrustPolicyReply::Err { message, .. } => {
            assert!(
                message.contains("not canonical"),
                "expected non-canonical rejection; got {message}"
            );
        }
        other => panic!("expected Err; got {other:?}"),
    }
    // RuleStore must NOT have been touched at either form.
    assert!(!rs.is_trusted(&dotted, &actual).unwrap());
    assert!(!rs.is_trusted(&canonical, &actual).unwrap());
}
