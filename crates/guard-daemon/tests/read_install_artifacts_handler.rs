use guard_daemon::handlers::read_install_artifacts::handle_read_install_artifacts;
use guard_daemon::install_artifacts::InstallArtifactStore;
use guard_daemon::rule_store::RuleStore;
use guard_ipc::ReadInstallArtifactsReply;

fn fresh_db() -> (tempfile::TempDir, std::path::PathBuf) {
    let dir = tempfile::tempdir().expect("tempdir");
    let db = dir.path().join("stt-guard.db");
    {
        let _r = RuleStore::open(&db).expect("migrate");
    }
    (dir, db)
}

#[test]
fn empty_store_returns_empty_list() {
    let (_dir, db) = fresh_db();
    let store = InstallArtifactStore::open(&db).unwrap();
    let r = handle_read_install_artifacts(&store);
    match r {
        ReadInstallArtifactsReply::Ok { artifacts, .. } => assert!(artifacts.is_empty()),
        _ => panic!("expected Ok"),
    }
}

#[test]
fn populated_store_returns_entries() {
    let (_dir, db) = fresh_db();
    let store = InstallArtifactStore::open(&db).unwrap();
    store
        .insert("launchagent", "/tmp/a.plist", None, "0.3.0")
        .unwrap();
    store
        .insert("init_script", "/tmp/init.sh", None, "0.3.0")
        .unwrap();
    let r = handle_read_install_artifacts(&store);
    match r {
        ReadInstallArtifactsReply::Ok { artifacts, .. } => assert_eq!(artifacts.len(), 2),
        _ => panic!("expected Ok"),
    }
}
