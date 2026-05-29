use guard_core::{MatchType, RuleKind, RuleTier};
use guard_daemon::rule_store::RuleStore;
use std::os::unix::fs::PermissionsExt;
use tempfile::TempDir;

fn store() -> (TempDir, RuleStore) {
    let tmp = TempDir::new().unwrap();
    let p = guard_core::paths::db_path(tmp.path());
    let s = RuleStore::open(&p).expect("open");
    (tmp, s)
}

#[test]
fn open_creates_db_and_runs_migration() {
    let (tmp, _s) = store();
    let p = guard_core::paths::db_path(tmp.path());
    assert!(p.exists(), "DB file should exist after open");
}

#[test]
fn open_is_idempotent() {
    let tmp = TempDir::new().unwrap();
    let p = guard_core::paths::db_path(tmp.path());
    let s1 = RuleStore::open(&p).expect("open #1");
    drop(s1); // close
    let _s2 = RuleStore::open(&p).expect("open #2");
    // No error means migrations are idempotent.
}

#[test]
fn db_file_has_mode_0600() {
    let (tmp, _s) = store();
    let p = guard_core::paths::db_path(tmp.path());
    let mode = std::fs::metadata(&p).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600, "DB file should be mode 0600; got {mode:o}");
}

#[test]
fn all_user_rules_empty_initially() {
    let (_tmp, s) = store();
    let rules = s.all_user_rules().expect("all_user_rules");
    assert_eq!(rules.len(), 0);
}

#[test]
fn all_user_rules_maps_kind_to_user_tier() {
    use rusqlite::{Connection, params};
    let tmp = TempDir::new().unwrap();
    let p = guard_core::paths::db_path(tmp.path());
    let _store = RuleStore::open(&p).expect("init schema");
    // Manually insert rows via direct sqlite (the CLI will do this in production).
    {
        let conn = Connection::open(&p).unwrap();
        conn.execute(
            "INSERT INTO rules (kind, match_type, pattern, reason, created_at) VALUES (?1, ?2, ?3, ?4, ?5)",
            params!["allow", "exact", "internal.acme.com", "corp registry", 0_i64],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO rules (kind, match_type, pattern, reason, created_at) VALUES (?1, ?2, ?3, ?4, ?5)",
            params!["deny", "suffix", ".prod.acme.com", "no prod traffic from this user", 0_i64],
        )
        .unwrap();
    }
    // Re-open via RuleStore and read back.
    let s = RuleStore::open(&p).expect("re-open");
    let rules = s.all_user_rules().expect("read");
    assert_eq!(rules.len(), 2);
    let allow = rules
        .iter()
        .find(|r| matches!(r.kind, RuleKind::Allow))
        .unwrap();
    assert!(
        matches!(allow.tier, RuleTier::UserAllow),
        "allow → UserAllow tier"
    );
    assert!(matches!(allow.match_type, MatchType::Exact));
    assert_eq!(allow.pattern, "internal.acme.com");

    let deny = rules
        .iter()
        .find(|r| matches!(r.kind, RuleKind::Deny))
        .unwrap();
    assert!(
        matches!(deny.tier, RuleTier::UserDeny),
        "deny → UserDeny tier"
    );
    assert!(matches!(deny.match_type, MatchType::Suffix));
    assert_eq!(deny.pattern, ".prod.acme.com");
}

#[test]
fn insert_user_rule_returns_rowid_and_appears_in_count() {
    let dir = tempfile::tempdir().expect("tempdir");
    let db = guard_core::paths::db_path(dir.path());
    let store = RuleStore::open(&db).expect("open");
    assert_eq!(store.count_user_rules().unwrap(), 0);
    let id1 = store
        .insert_user_rule("allow", "exact", "h.example.com", "approved")
        .expect("insert");
    let id2 = store
        .insert_user_rule("allow", "suffix", ".example.com", "approved")
        .expect("insert");
    assert!(id1 > 0 && id2 > id1);
    assert_eq!(store.count_user_rules().unwrap(), 2);
}

#[cfg(feature = "test-signer")]
fn signed_payload(
    kind: &str,
    match_type: &str,
    pattern: &str,
    reason: &str,
) -> (
    guard_core::RuleSignaturePayloadV1,
    guard_core::RuleSignatureV1,
) {
    let payload = guard_core::RuleSignaturePayloadV1::new(
        kind,
        match_type,
        pattern,
        reason,
        1_700_000_000_000,
        "test",
        Some("run-1".into()),
    );
    let signature =
        guard_core::rule_signature::test_support::sign_with_test_simulator(&payload).expect("sign");
    (payload, signature)
}

#[cfg(feature = "test-signer")]
#[test]
fn signed_user_rule_verifies_and_maps_to_entry() {
    let (_tmp, s) = store();
    let (payload, signature) = signed_payload("allow", "exact", "signed.example.com", "approved");
    s.register_trusted_rule_signer(&signature, "test signer")
        .expect("trust signer");
    s.insert_signed_user_rule(&payload, &signature)
        .expect("insert signed");
    let rules = s
        .all_verified_user_rules(guard_core::RuleSignaturePolicy::AllowTestSimulator)
        .expect("verified rules");
    assert_eq!(rules.len(), 1);
    assert_eq!(rules[0].pattern, "signed.example.com");
    assert!(matches!(rules[0].tier, RuleTier::UserAllow));
}

#[cfg(feature = "test-signer")]
#[test]
fn unsigned_legacy_row_fails_verified_read() {
    let (_tmp, s) = store();
    s.insert_user_rule("allow", "exact", "unsigned.example.com", "legacy")
        .expect("legacy insert");
    let err = s
        .all_verified_user_rules(guard_core::RuleSignaturePolicy::AllowTestSimulator)
        .expect_err("unsigned row must fail closed");
    assert!(err.to_string().contains("unsigned user rule present"));
}

#[cfg(feature = "test-signer")]
#[test]
fn orphan_signature_row_fails_verified_read() {
    use rusqlite::{Connection, params};
    let tmp = TempDir::new().unwrap();
    let p = guard_core::paths::db_path(tmp.path());
    let s = RuleStore::open(&p).expect("open");
    let (payload, signature) = signed_payload("allow", "exact", "good.example.com", "approved");
    s.register_trusted_rule_signer(&signature, "test signer")
        .expect("trust signer");
    let rule_id = s
        .insert_signed_user_rule(&payload, &signature)
        .expect("insert signed");
    drop(s);
    let conn = Connection::open(&p).unwrap();
    conn.execute("PRAGMA foreign_keys = OFF", []).unwrap();
    conn.execute(
        "DELETE FROM rule_signatures WHERE rule_id = ?1",
        params![rule_id],
    )
    .unwrap();
    conn.execute(
        "INSERT INTO rule_signatures (
            rule_id, scheme, signer_kind, public_key_x963, public_key_sha256,
            signature_der, signed_payload_sha256, signature_created_at,
            origin, run_uuid, payload_created_at
        ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
        params![
            rule_id + 10_000,
            signature.scheme,
            signature.signer_kind,
            signature.public_key_x963,
            signature.public_key_sha256,
            signature.signature_der,
            signature.signed_payload_sha256,
            signature.signature_created_at_unix_ms,
            payload.origin,
            payload.run_uuid,
            payload.created_at_unix_ms,
        ],
    )
    .unwrap();
    drop(conn);
    let s = RuleStore::open(&p).expect("reopen");
    let err = s
        .all_verified_user_rules(guard_core::RuleSignaturePolicy::AllowTestSimulator)
        .expect_err("orphan signature must fail closed");
    assert!(err.to_string().contains("unsigned user rule present"));
}

#[cfg(feature = "test-signer")]
#[test]
fn tampered_signed_rule_fails_verified_read() {
    use rusqlite::{Connection, params};
    let tmp = TempDir::new().unwrap();
    let p = guard_core::paths::db_path(tmp.path());
    let s = RuleStore::open(&p).expect("open");
    let (payload, signature) = signed_payload("allow", "exact", "good.example.com", "approved");
    s.register_trusted_rule_signer(&signature, "test signer")
        .expect("trust signer");
    let rule_id = s
        .insert_signed_user_rule(&payload, &signature)
        .expect("insert signed");
    drop(s);
    let conn = Connection::open(&p).unwrap();
    conn.execute(
        "UPDATE rules SET pattern = ?1 WHERE id = ?2",
        params!["evil.example.com", rule_id],
    )
    .unwrap();
    let s = RuleStore::open(&p).expect("reopen");
    let err = s
        .all_verified_user_rules(guard_core::RuleSignaturePolicy::AllowTestSimulator)
        .expect_err("tamper must fail closed");
    assert!(err.to_string().contains("signature"));
}
