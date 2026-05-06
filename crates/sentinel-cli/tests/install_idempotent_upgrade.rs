use sentinel_cli::install::upgrade::diff;
use sentinel_ipc::InstallArtifact;

fn art(kind: &str, path: &str, hash: Option<&str>) -> InstallArtifact {
    InstallArtifact {
        artifact_kind: kind.into(),
        target_path: path.into(),
        content_hash: hash.map(|s| s.to_string()),
        installed_at_ms: 0,
        sentinel_version: "0.3.0".into(),
    }
}

#[test]
fn diff_finds_added_replaced_removed() {
    let existing = vec![
        art("launchagent", "/tmp/a.plist", Some("hash-v1")),
        art("init_script", "/tmp/init.sh", Some("init-v1")),
        art("marker_block", "/tmp/.zshrc", Some("marker-v1")),
    ];
    let proposed: Vec<(String, String, Option<String>)> = vec![
        ("launchagent".into(), "/tmp/a.plist".into(), Some("hash-v1".into())),  // unchanged
        ("init_script".into(), "/tmp/init.sh".into(), Some("init-v2".into())),  // replaced
        ("log_dir".into(), "/tmp/logs".into(), None),                           // added
    ];
    let (add, replace, remove) = diff(&existing, &proposed);
    assert_eq!(add, vec![2]);                         // log_dir is new
    assert_eq!(replace, vec![1]);                     // init_script hash changed
    assert!(remove.iter().any(|i| existing[*i].artifact_kind == "marker_block"));
}

#[test]
fn diff_empty_existing_all_added() {
    let proposed: Vec<(String, String, Option<String>)> = vec![
        ("launchagent".into(), "/tmp/a".into(), None),
        ("init_script".into(), "/tmp/b".into(), None),
    ];
    let (add, replace, remove) = diff(&[], &proposed);
    assert_eq!(add, vec![0, 1]);
    assert!(replace.is_empty());
    assert!(remove.is_empty());
}
