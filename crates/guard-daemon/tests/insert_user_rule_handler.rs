use guard_daemon::handlers::insert_user_rule::handle_insert_user_rule;
use guard_daemon::rule_store::RuleStore;
use guard_ipc::{IPC_SCHEMA_V3, InsertUserRule, InsertUserRuleReply};

fn req(kind: &str, match_type: &str, pattern: &str, reason: &str) -> InsertUserRule {
    InsertUserRule {
        schema_version: IPC_SCHEMA_V3,
        kind: kind.into(),
        match_type: match_type.into(),
        pattern: pattern.into(),
        reason: reason.into(),
    }
}

#[test]
fn happy_path_returns_rule_id() {
    let dir = tempfile::tempdir().expect("tempdir");
    let store = RuleStore::open(&dir.path().join("stt-guard.db")).expect("open");
    let r = handle_insert_user_rule(&req("allow", "exact", "h.example.com", "approved"), &store);
    match r {
        InsertUserRuleReply::Ok { rule_id, .. } => assert!(rule_id > 0),
        InsertUserRuleReply::Err { message, .. } => panic!("expected Ok, got Err({message})"),
    }
}

#[test]
fn rejects_bad_kind() {
    let dir = tempfile::tempdir().unwrap();
    let store = RuleStore::open(&dir.path().join("stt-guard.db")).unwrap();
    let r = handle_insert_user_rule(&req("bogus", "exact", "h", "ok"), &store);
    assert!(matches!(r, InsertUserRuleReply::Err { .. }));
}

#[test]
fn rejects_bad_match_type() {
    let dir = tempfile::tempdir().unwrap();
    let store = RuleStore::open(&dir.path().join("stt-guard.db")).unwrap();
    let r = handle_insert_user_rule(&req("allow", "regex", "h", "ok"), &store);
    assert!(matches!(r, InsertUserRuleReply::Err { .. }));
}

#[test]
fn rejects_empty_reason() {
    let dir = tempfile::tempdir().unwrap();
    let store = RuleStore::open(&dir.path().join("stt-guard.db")).unwrap();
    let r = handle_insert_user_rule(&req("allow", "exact", "h", "   "), &store);
    assert!(matches!(r, InsertUserRuleReply::Err { .. }));
}

#[test]
fn rejects_empty_pattern() {
    let dir = tempfile::tempdir().unwrap();
    let store = RuleStore::open(&dir.path().join("stt-guard.db")).unwrap();
    let r = handle_insert_user_rule(&req("allow", "exact", "  ", "ok"), &store);
    assert!(matches!(r, InsertUserRuleReply::Err { .. }));
}
