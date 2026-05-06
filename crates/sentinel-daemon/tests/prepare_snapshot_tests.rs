use sentinel_core::{AllowlistEntry, MatchType, RuleKind, RuleTier, SCHEMA_V2};
use sentinel_daemon::handlers::prepare_snapshot::handle_prepare_snapshot;
use sentinel_daemon::rule_store::RuleStore;
use sentinel_daemon::tracked::ProcessTree;
use std::sync::Arc;
use tempfile::TempDir;

fn allow(pattern: &str, tier: RuleTier) -> AllowlistEntry {
    AllowlistEntry {
        kind: RuleKind::Allow,
        tier,
        match_type: MatchType::Exact,
        pattern: pattern.into(),
        reason: "t".into(),
    }
}

#[test]
fn prepare_snapshot_writes_per_run_files_and_returns_ok() {
    let tmp = TempDir::new().unwrap();
    let state_dir = tmp.path().to_path_buf();
    sentinel_daemon::state_dir::ensure_runs_dir(&state_dir).unwrap();
    let rs = RuleStore::open(&sentinel_daemon::state_dir::db_path(&state_dir)).unwrap();
    let pt = Arc::new(ProcessTree::new());
    let curated = vec![allow("registry.npmjs.org", RuleTier::CuratedAllow)];

    // Use a cwd with no .sentinel.toml.
    let cwd = tmp.path().to_path_buf();
    let reply = handle_prepare_snapshot(&cwd, &curated, &rs, &pt, &state_dir);

    match reply {
        sentinel_ipc::SnapshotReply::Ok {
            manifest_path,
            run_uuid,
            ..
        } => {
            assert!(!manifest_path.is_empty());
            assert!(!run_uuid.is_empty());
            // The per-run snapshot file should exist.
            let snap_path =
                sentinel_daemon::state_dir::run_snapshot_path(&state_dir, &run_uuid);
            assert!(snap_path.exists(), "per-run snapshot file written");
            // The matching manifest file should exist.
            let man_path =
                sentinel_daemon::state_dir::run_manifest_path(&state_dir, &run_uuid);
            assert!(man_path.exists(), "per-run manifest file written");
            // The RunRecord should be in the tree.
            assert!(pt.get_run(&run_uuid).is_some());
        }
        sentinel_ipc::SnapshotReply::Err { message, .. } => {
            panic!("expected Ok; got Err: {message}");
        }
    }
}

#[test]
fn prepare_snapshot_includes_curated_entries_sorted_by_tier() {
    let tmp = TempDir::new().unwrap();
    let state_dir = tmp.path().to_path_buf();
    sentinel_daemon::state_dir::ensure_runs_dir(&state_dir).unwrap();
    let rs = RuleStore::open(&sentinel_daemon::state_dir::db_path(&state_dir)).unwrap();
    let pt = Arc::new(ProcessTree::new());
    let curated = vec![
        AllowlistEntry {
            kind: RuleKind::Deny,
            tier: RuleTier::BuiltinDeny,
            match_type: MatchType::Suffix,
            pattern: ".workers.dev".into(),
            reason: "abuse-pattern".into(),
        },
        AllowlistEntry {
            kind: RuleKind::Allow,
            tier: RuleTier::CuratedAllow,
            match_type: MatchType::Exact,
            pattern: "registry.npmjs.org".into(),
            reason: "npm registry".into(),
        },
    ];
    let reply = handle_prepare_snapshot(tmp.path(), &curated, &rs, &pt, &state_dir);
    match reply {
        sentinel_ipc::SnapshotReply::Ok { run_uuid, .. } => {
            let snap_path =
                sentinel_daemon::state_dir::run_snapshot_path(&state_dir, &run_uuid);
            let bytes = std::fs::read(&snap_path).unwrap();
            let snap = sentinel_core::Snapshot::decode(&bytes).expect("decode");
            assert_eq!(snap.schema_version, SCHEMA_V2);
            // Entries pre-sorted by tier ASC: BuiltinDeny (0) before CuratedAllow (1).
            assert!(snap.entries.len() >= 2);
            assert!(snap.entries[0].tier <= snap.entries[1].tier);
            // First entry is BuiltinDeny (the .workers.dev rule).
            assert!(matches!(snap.entries[0].tier, RuleTier::BuiltinDeny));
        }
        sentinel_ipc::SnapshotReply::Err { message, .. } => {
            panic!("expected Ok; got Err: {message}");
        }
    }
}

#[test]
fn prepare_snapshot_with_trusted_sentinel_toml_includes_project_rules() {
    let tmp = TempDir::new().unwrap();
    let state_dir = tmp.path().to_path_buf();
    sentinel_daemon::state_dir::ensure_runs_dir(&state_dir).unwrap();
    let rs = RuleStore::open(&sentinel_daemon::state_dir::db_path(&state_dir)).unwrap();
    let pt = Arc::new(ProcessTree::new());
    let curated = vec![];

    // Lay out a project with a trusted .sentinel.toml.
    let proj = tmp.path().join("proj");
    std::fs::create_dir_all(&proj).unwrap();
    let toml_path = proj.join(".sentinel.toml");
    std::fs::write(
        &toml_path,
        "version = 1\n[[rules]]\nkind = \"allow\"\nmatch = \"exact\"\npattern = \"internal.acme.com\"\nreason = \"corp registry\"\n",
    )
    .unwrap();
    let canonical = toml_path.canonicalize().unwrap();
    let sha = sentinel_daemon::policy_file::sha256_of_file(&canonical).unwrap();
    rs.insert_trusted(&canonical.display().to_string(), &sha, "cli")
        .unwrap();

    let reply = handle_prepare_snapshot(&proj, &curated, &rs, &pt, &state_dir);
    match reply {
        sentinel_ipc::SnapshotReply::Ok { run_uuid, .. } => {
            let snap_path =
                sentinel_daemon::state_dir::run_snapshot_path(&state_dir, &run_uuid);
            let bytes = std::fs::read(&snap_path).unwrap();
            let snap = sentinel_core::Snapshot::decode(&bytes).expect("decode");
            // Project rules tagged ProjectAllow.
            let has_project = snap.entries.iter().any(|e| {
                e.pattern == "internal.acme.com" && matches!(e.tier, RuleTier::ProjectAllow)
            });
            assert!(has_project, "project rule should appear with ProjectAllow tier");
            assert!(snap.project_toml_path.is_some());
            assert_eq!(snap.project_toml_sha256.as_deref(), Some(sha.as_str()));
        }
        sentinel_ipc::SnapshotReply::Err { message, .. } => {
            panic!("expected Ok; got Err: {message}");
        }
    }
}
