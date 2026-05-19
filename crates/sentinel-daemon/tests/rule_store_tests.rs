use sentinel_core::{MatchType, RuleKind, RuleTier};
use sentinel_daemon::rule_store::RuleStore;
use std::os::unix::fs::PermissionsExt;
use tempfile::TempDir;

fn store() -> (TempDir, RuleStore) {
    let tmp = TempDir::new().unwrap();
    let p = tmp.path().join("sentinel.db");
    let s = RuleStore::open(&p).expect("open");
    (tmp, s)
}

#[test]
fn open_creates_db_and_runs_migration() {
    let (tmp, _s) = store();
    let p = tmp.path().join("sentinel.db");
    assert!(p.exists(), "DB file should exist after open");
}

#[test]
fn open_is_idempotent() {
    let tmp = TempDir::new().unwrap();
    let p = tmp.path().join("sentinel.db");
    let _s1 = RuleStore::open(&p).expect("open #1");
    drop(_s1); // close
    let _s2 = RuleStore::open(&p).expect("open #2");
    // No error means migrations are idempotent.
}

#[test]
fn db_file_has_mode_0600() {
    let (tmp, _s) = store();
    let p = tmp.path().join("sentinel.db");
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
    use rusqlite::{params, Connection};
    let tmp = TempDir::new().unwrap();
    let p = tmp.path().join("sentinel.db");
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
    let db = dir.path().join("sentinel.db");
    let store = RuleStore::open(&db).expect("open");
    assert_eq!(store.count_user_rules().unwrap(), 0);
    let id1 = store.insert_user_rule("allow", "exact", "h.example.com", "approved").expect("insert");
    let id2 = store.insert_user_rule("allow", "suffix", ".example.com", "approved").expect("insert");
    assert!(id1 > 0 && id2 > id1);
    assert_eq!(store.count_user_rules().unwrap(), 2);
}
