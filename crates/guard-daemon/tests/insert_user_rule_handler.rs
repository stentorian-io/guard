#![cfg(feature = "test-signer")]

use guard_core::{RuleSignaturePayloadV1, RuleSignaturePolicy};
use guard_daemon::handlers::insert_user_rule::handle_insert_user_rule;
use guard_daemon::rule_store::RuleStore;
use guard_ipc::{IPC_SCHEMA_V5, InsertUserRule, InsertUserRuleReply};

fn signed_req(kind: &str, match_type: &str, pattern: &str, reason: &str) -> InsertUserRule {
    let created_at_unix_ms = 1_700_000_000_000;
    let payload = RuleSignaturePayloadV1::new(
        kind,
        match_type,
        pattern,
        reason,
        created_at_unix_ms,
        "test",
        Some("run-1".into()),
    );
    let signature =
        guard_core::rule_signature::test_support::sign_with_test_simulator(&payload).expect("sign");
    InsertUserRule {
        schema_version: IPC_SCHEMA_V5,
        kind: kind.into(),
        match_type: match_type.into(),
        pattern: pattern.into(),
        reason: reason.into(),
        created_at_unix_ms,
        origin: "test".into(),
        run_uuid: Some("run-1".into()),
        signature: Some(signature),
    }
}

fn unsigned_req(kind: &str, match_type: &str, pattern: &str, reason: &str) -> InsertUserRule {
    InsertUserRule {
        schema_version: guard_ipc::IPC_SCHEMA_V3,
        kind: kind.into(),
        match_type: match_type.into(),
        pattern: pattern.into(),
        reason: reason.into(),
        created_at_unix_ms: 0,
        origin: String::new(),
        run_uuid: None,
        signature: None,
    }
}

#[test]
fn signed_happy_path_returns_rule_id_under_test_policy() {
    let dir = tempfile::tempdir().expect("tempdir");
    let store = RuleStore::open(&guard_core::paths::db_path(dir.path())).expect("open");
    let req = signed_req("allow", "exact", "h.example.com", "approved");
    store
        .register_trusted_rule_signer(req.signature.as_ref().unwrap(), "test signer")
        .expect("trust signer");
    let r = handle_insert_user_rule(&req, &store, RuleSignaturePolicy::AllowTestSimulator);
    match r {
        InsertUserRuleReply::Ok { rule_id, .. } => assert!(rule_id > 0),
        InsertUserRuleReply::Err { message, .. } => panic!("expected Ok, got Err({message})"),
    }
}

#[test]
fn rejects_unsigned_legacy_request() {
    let dir = tempfile::tempdir().expect("tempdir");
    let store = RuleStore::open(&guard_core::paths::db_path(dir.path())).expect("open");
    let r = handle_insert_user_rule(
        &unsigned_req("allow", "exact", "h.example.com", "approved"),
        &store,
        RuleSignaturePolicy::AllowTestSimulator,
    );
    assert!(
        matches!(r, InsertUserRuleReply::Err { message, .. } if message.contains("signed rule attestation required") || message.contains("created_at"))
    );
}

#[test]
fn rejects_test_signer_under_production_policy() {
    let dir = tempfile::tempdir().expect("tempdir");
    let store = RuleStore::open(&guard_core::paths::db_path(dir.path())).expect("open");
    let r = handle_insert_user_rule(
        &signed_req("allow", "exact", "h.example.com", "approved"),
        &store,
        RuleSignaturePolicy::Production,
    );
    assert!(
        matches!(r, InsertUserRuleReply::Err { message, .. } if message.contains("unsupported rule signer kind"))
    );
}

#[test]
fn rejects_bad_kind() {
    let dir = tempfile::tempdir().unwrap();
    let store = RuleStore::open(&guard_core::paths::db_path(dir.path())).unwrap();
    let r = handle_insert_user_rule(
        &signed_req("bogus", "exact", "h", "ok"),
        &store,
        RuleSignaturePolicy::AllowTestSimulator,
    );
    assert!(matches!(r, InsertUserRuleReply::Err { .. }));
}

#[test]
fn rejects_bad_match_type() {
    let dir = tempfile::tempdir().unwrap();
    let store = RuleStore::open(&guard_core::paths::db_path(dir.path())).unwrap();
    let r = handle_insert_user_rule(
        &signed_req("allow", "regex", "h", "ok"),
        &store,
        RuleSignaturePolicy::AllowTestSimulator,
    );
    assert!(matches!(r, InsertUserRuleReply::Err { .. }));
}

#[test]
fn rejects_empty_reason() {
    let dir = tempfile::tempdir().unwrap();
    let store = RuleStore::open(&guard_core::paths::db_path(dir.path())).unwrap();
    let r = handle_insert_user_rule(
        &signed_req("allow", "exact", "h", "   "),
        &store,
        RuleSignaturePolicy::AllowTestSimulator,
    );
    assert!(matches!(r, InsertUserRuleReply::Err { .. }));
}

#[test]
fn rejects_empty_pattern() {
    let dir = tempfile::tempdir().unwrap();
    let store = RuleStore::open(&guard_core::paths::db_path(dir.path())).unwrap();
    let r = handle_insert_user_rule(
        &signed_req("allow", "exact", "  ", "ok"),
        &store,
        RuleSignaturePolicy::AllowTestSimulator,
    );
    assert!(matches!(r, InsertUserRuleReply::Err { .. }));
}

#[test]
fn rejects_tampered_payload() {
    let dir = tempfile::tempdir().unwrap();
    let store = RuleStore::open(&guard_core::paths::db_path(dir.path())).unwrap();
    let mut req = signed_req("allow", "exact", "h.example.com", "approved");
    req.pattern = "evil.example.com".into();
    let r = handle_insert_user_rule(&req, &store, RuleSignaturePolicy::AllowTestSimulator);
    assert!(
        matches!(r, InsertUserRuleReply::Err { message, .. } if message.contains("PayloadHashMismatch") || message.contains("payload hash mismatch") || message.contains("signature"))
    );
}
