//! v0.3 — InstallArtifactStore CRUD tests.

use guard_daemon::install_artifacts::{InstallArtifactStore, read_via_db};
use guard_daemon::rule_store::RuleStore;

fn fresh_db() -> (tempfile::TempDir, std::path::PathBuf) {
    let dir = tempfile::tempdir().expect("tempdir");
    let db = guard_core::paths::db_path(dir.path());
    // RuleStore::open runs migrations; we then drop it so the install_artifacts
    // store and the read_via_db helper can open fresh handles.
    {
        let _rs = RuleStore::open(&db).expect("rule_store open runs migrations");
    }
    (dir, db)
}

#[test]
fn insert_then_list_round_trip() {
    let (_dir, db) = fresh_db();
    let store = InstallArtifactStore::open(&db).expect("open");
    store
        .insert("launchagent", "/tmp/agent.plist", Some("abc"), "0.3.0")
        .expect("insert");
    let rows = store.list_all().expect("list");
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].artifact_kind, "launchagent");
    assert_eq!(rows[0].target_path, "/tmp/agent.plist");
    assert_eq!(rows[0].content_hash.as_deref(), Some("abc"));
    assert_eq!(rows[0].guard_version, "0.3.0");
}

#[test]
fn insert_or_replace_idempotent() {
    let (_dir, db) = fresh_db();
    let store = InstallArtifactStore::open(&db).expect("open");
    store
        .insert("init_script", "/tmp/init.sh", Some("v1hash"), "0.3.0")
        .expect("first");
    store
        .insert("init_script", "/tmp/init.sh", Some("v2hash"), "0.3.1")
        .expect("replace");
    let rows = store.list_all().expect("list");
    assert_eq!(rows.len(), 1, "INSERT OR REPLACE collapses on PK");
    assert_eq!(rows[0].content_hash.as_deref(), Some("v2hash"));
    assert_eq!(rows[0].guard_version, "0.3.1");
}

#[test]
fn delete_by_pk() {
    let (_dir, db) = fresh_db();
    let store = InstallArtifactStore::open(&db).expect("open");
    store
        .insert("marker_block", "/tmp/.zshrc", None, "0.3.0")
        .expect("insert");
    let removed = store.delete("marker_block", "/tmp/.zshrc").expect("delete");
    assert_eq!(removed, 1);
    assert!(store.list_all().expect("list").is_empty());
}

#[test]
fn delete_all_clears_table() {
    let (_dir, db) = fresh_db();
    let store = InstallArtifactStore::open(&db).expect("open");
    store
        .insert("launchagent", "/tmp/a.plist", None, "0.3.0")
        .unwrap();
    store
        .insert("init_script", "/tmp/init.sh", None, "0.3.0")
        .unwrap();
    let n = store.delete_all().expect("delete_all");
    assert_eq!(n, 2);
    assert!(store.list_all().expect("list").is_empty());
}

#[test]
fn check_constraint_rejects_bogus_kind() {
    let (_dir, db) = fresh_db();
    let store = InstallArtifactStore::open(&db).expect("open");
    let err = store
        .insert("not_a_real_kind", "/tmp/x", None, "0.3.0")
        .unwrap_err();
    let msg = err.to_string();
    assert!(
        msg.contains("CHECK") || msg.contains("constraint"),
        "got: {msg}"
    );
}

#[test]
fn read_via_db_works_when_no_handle_open() {
    let (_dir, db) = fresh_db();
    {
        let store = InstallArtifactStore::open(&db).expect("open");
        store
            .insert("log_dir", "/tmp/logs", None, "0.3.0")
            .expect("insert");
    } // drop store; only the file remains
    let rows = read_via_db(&db).expect("read_via_db");
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].artifact_kind, "log_dir");
}
