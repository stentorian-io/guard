use guard_core::{AllowlistEntry, MatchType, RuleKind, RuleTier, SCHEMA_V2};
#[cfg(feature = "test-signer")]
use guard_daemon::gap_detector::GapDetector;
use guard_daemon::handlers::prepare_snapshot::handle_prepare_snapshot;
#[cfg(feature = "test-signer")]
use guard_daemon::handlers::prepare_snapshot::{
    handle_prepare_snapshot_inputs_full, handle_publish_signed_snapshot_full,
};
#[cfg(feature = "test-signer")]
use guard_daemon::ipc_server::{DaemonState, PendingSnapshotInput};
use guard_daemon::rule_store::RuleStore;
use guard_daemon::tracked::ProcessTree;
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

#[cfg(feature = "test-signer")]
fn insert_signed_allow(rs: &RuleStore, pattern: &str) -> i64 {
    let payload = guard_core::RuleSignaturePayloadV1::new(
        "allow",
        "exact",
        pattern,
        "approved",
        1_700_000_000_000,
        "test",
        Some("run-1".into()),
    );
    let signature =
        guard_core::rule_signature::test_support::sign_with_test_simulator(&payload).expect("sign");
    rs.register_trusted_rule_signer(&signature, "test signer")
        .expect("trust signer");
    rs.insert_signed_user_rule(&payload, &signature)
        .expect("insert signed")
}

#[cfg(feature = "test-signer")]
fn signed_snapshot_request(
    run_uuid: &str,
) -> (
    guard_core::SnapshotBuildInput,
    Vec<u8>,
    guard_core::SnapshotSignatureV1,
) {
    let input = guard_core::SnapshotBuildInput {
        run_uuid: run_uuid.to_string(),
        generated_at_unix_ms: 1_700_000_000_000,
        curated_entries: vec![allow("registry.npmjs.org", RuleTier::CuratedAllow)],
        disabled_curated_patterns: std::collections::BTreeSet::new(),
        verified_user_entries: vec![],
        lockfile_entries: vec![],
    };
    let bytes = guard_core::build_snapshot_bytes(input.clone()).expect("build snapshot");
    let payload = guard_core::SnapshotSignaturePayloadV1::new(
        run_uuid,
        guard_core::sha256_hex(&bytes),
        1_700_000_000_000,
    );
    let signature =
        guard_core::rule_signature::test_support::sign_snapshot_with_test_simulator(&payload)
            .expect("sign snapshot");
    (input, bytes, signature)
}

#[cfg(feature = "test-signer")]
fn daemon_state_for_publish(
    state_dir: &std::path::Path,
    input: &guard_core::SnapshotBuildInput,
    signature: &guard_core::SnapshotSignatureV1,
    trust_signer: bool,
) -> Arc<DaemonState> {
    guard_daemon::state_dir::ensure_runs_dir(state_dir).unwrap();
    let rule_store =
        Arc::new(RuleStore::open(&guard_daemon::state_dir::db_path(state_dir)).unwrap());
    if trust_signer {
        rule_store
            .register_trusted_rule_signer_key(
                &signature.public_key_sha256,
                &signature.signer_kind,
                &signature.public_key_x963,
                "test snapshot signer",
            )
            .expect("trust signer");
    }
    let mut state = DaemonState::new(
        Arc::new(ProcessTree::new()),
        Arc::new(GapDetector::new()),
        rule_store,
        Arc::new(vec![]),
        state_dir.to_path_buf(),
    );
    state.rule_signature_policy = guard_core::RuleSignaturePolicy::AllowTestSimulator;
    state.pending_snapshot_inputs.lock().unwrap().insert(
        input.run_uuid.clone(),
        PendingSnapshotInput {
            input: input.clone(),
            is_tty: false,
            baseline_mode: false,
            prepared_at: std::time::Instant::now(),
        },
    );
    Arc::new(state)
}

#[test]
fn prepare_snapshot_writes_per_run_files_and_returns_ok() {
    let tmp = TempDir::new().unwrap();
    let state_dir = tmp.path().to_path_buf();
    guard_daemon::state_dir::ensure_runs_dir(&state_dir).unwrap();
    let rs = RuleStore::open(&guard_daemon::state_dir::db_path(&state_dir)).unwrap();
    let pt = Arc::new(ProcessTree::new());
    let curated = vec![allow("registry.npmjs.org", RuleTier::CuratedAllow)];

    let cwd = tmp.path().to_path_buf();
    let reply = handle_prepare_snapshot(
        &cwd,
        &curated,
        &rs,
        &pt,
        &state_dir,
        guard_core::RuleSignaturePolicy::AllowTestSimulator,
        false,
        false,
    );

    match reply {
        guard_ipc::SnapshotReply::Ok {
            manifest_path,
            run_uuid,
            ..
        } => {
            assert!(!manifest_path.is_empty());
            assert!(!run_uuid.is_empty());
            let snap_path = guard_daemon::state_dir::run_snapshot_path(&state_dir, &run_uuid);
            assert!(snap_path.exists(), "per-run snapshot file written");
            let man_path = guard_daemon::state_dir::run_manifest_path(&state_dir, &run_uuid);
            assert!(man_path.exists(), "per-run manifest file written");
            assert!(pt.get_run(&run_uuid).is_some());
        }
        guard_ipc::SnapshotReply::Err { message, .. } => {
            panic!("expected Ok; got Err: {message}");
        }
    }
}

#[test]
fn prepare_snapshot_includes_curated_entries_sorted_by_tier() {
    let tmp = TempDir::new().unwrap();
    let state_dir = tmp.path().to_path_buf();
    guard_daemon::state_dir::ensure_runs_dir(&state_dir).unwrap();
    let rs = RuleStore::open(&guard_daemon::state_dir::db_path(&state_dir)).unwrap();
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
    let reply = handle_prepare_snapshot(
        tmp.path(),
        &curated,
        &rs,
        &pt,
        &state_dir,
        guard_core::RuleSignaturePolicy::AllowTestSimulator,
        false,
        false,
    );
    match reply {
        guard_ipc::SnapshotReply::Ok { run_uuid, .. } => {
            let snap_path = guard_daemon::state_dir::run_snapshot_path(&state_dir, &run_uuid);
            let bytes = std::fs::read(&snap_path).unwrap();
            let snap = guard_core::Snapshot::decode(&bytes).expect("decode");
            assert_eq!(snap.schema_version, SCHEMA_V2);
            assert!(snap.entries.len() >= 2);
            assert!(snap.entries[0].tier <= snap.entries[1].tier);
            assert!(matches!(snap.entries[0].tier, RuleTier::BuiltinDeny));
        }
        guard_ipc::SnapshotReply::Err { message, .. } => {
            panic!("expected Ok; got Err: {message}");
        }
    }
}

#[cfg(feature = "test-signer")]
#[test]
fn prepare_snapshot_includes_verified_signed_user_rule() {
    let tmp = TempDir::new().unwrap();
    let state_dir = tmp.path().to_path_buf();
    guard_daemon::state_dir::ensure_runs_dir(&state_dir).unwrap();
    let rs = RuleStore::open(&guard_daemon::state_dir::db_path(&state_dir)).unwrap();
    insert_signed_allow(&rs, "signed.example.com");
    let pt = Arc::new(ProcessTree::new());
    let curated = Vec::new();

    let reply = handle_prepare_snapshot(
        tmp.path(),
        &curated,
        &rs,
        &pt,
        &state_dir,
        guard_core::RuleSignaturePolicy::AllowTestSimulator,
        false,
        false,
    );
    match reply {
        guard_ipc::SnapshotReply::Ok { run_uuid, .. } => {
            let snap_path = guard_daemon::state_dir::run_snapshot_path(&state_dir, &run_uuid);
            let bytes = std::fs::read(&snap_path).unwrap();
            let snap = guard_core::Snapshot::decode(&bytes).expect("decode");
            assert!(snap
                .entries
                .iter()
                .any(|e| e.pattern == "signed.example.com"));
        }
        guard_ipc::SnapshotReply::Err { message, .. } => {
            panic!("expected Ok; got Err: {message}");
        }
    }
}

#[cfg(feature = "test-signer")]
#[test]
fn prepare_snapshot_fails_closed_on_tampered_user_rule() {
    use rusqlite::{params, Connection};

    let tmp = TempDir::new().unwrap();
    let state_dir = tmp.path().to_path_buf();
    guard_daemon::state_dir::ensure_runs_dir(&state_dir).unwrap();
    let db = guard_daemon::state_dir::db_path(&state_dir);
    let rs = RuleStore::open(&db).unwrap();
    let rule_id = insert_signed_allow(&rs, "signed.example.com");
    drop(rs);
    let conn = Connection::open(&db).unwrap();
    conn.execute(
        "UPDATE rules SET pattern = ?1 WHERE id = ?2",
        params!["evil.example.com", rule_id],
    )
    .unwrap();
    drop(conn);
    let rs = RuleStore::open(&db).unwrap();
    let pt = Arc::new(ProcessTree::new());
    let curated = Vec::new();

    let reply = handle_prepare_snapshot(
        tmp.path(),
        &curated,
        &rs,
        &pt,
        &state_dir,
        guard_core::RuleSignaturePolicy::AllowTestSimulator,
        false,
        false,
    );
    assert!(matches!(
        reply,
        guard_ipc::SnapshotReply::Err { message, .. }
            if message.contains("user rule signature verification failed")
    ));
}

#[cfg(feature = "test-signer")]
#[test]
fn prepare_snapshot_inputs_prunes_expired_pending_inputs() {
    let tmp = TempDir::new().unwrap();
    let state_dir = tmp.path();
    let (input, _bytes, signature) = signed_snapshot_request("expired-run");
    let state = daemon_state_for_publish(state_dir, &input, &signature, true);
    state.pending_snapshot_inputs.lock().unwrap().insert(
        "expired-run".to_string(),
        PendingSnapshotInput {
            input,
            is_tty: false,
            baseline_mode: false,
            prepared_at: std::time::Instant::now() - std::time::Duration::from_secs(11 * 60),
        },
    );
    let reply = handle_prepare_snapshot_inputs_full(&state, tmp.path(), false, false);
    assert!(matches!(reply, guard_ipc::SnapshotInputsReply::Ok { .. }));
    let pending = state.pending_snapshot_inputs.lock().unwrap();
    assert!(!pending.contains_key("expired-run"));
    assert_eq!(pending.len(), 1, "new prepare should remain pending");
}

#[cfg(feature = "test-signer")]
#[test]
fn publish_signed_snapshot_writes_exact_bytes_and_signature_manifest() {
    let tmp = TempDir::new().unwrap();
    let state_dir = tmp.path();
    let run_uuid = "signed-publish-ok";
    let (input, bytes, signature) = signed_snapshot_request(run_uuid);
    let state = daemon_state_for_publish(state_dir, &input, &signature, true);
    let reply = handle_publish_signed_snapshot_full(
        &state,
        guard_ipc::PublishSignedSnapshot::new(run_uuid, bytes.clone(), signature, false, false),
    );
    let guard_ipc::SnapshotReply::Ok {
        run_uuid: reply_uuid,
        ..
    } = reply
    else {
        panic!("expected publish ok, got {reply:?}");
    };
    assert_eq!(reply_uuid, run_uuid);
    let snap_path = guard_daemon::state_dir::run_snapshot_path(state_dir, run_uuid);
    assert_eq!(std::fs::read(snap_path).unwrap(), bytes);
    let manifest = std::fs::read_to_string(guard_daemon::state_dir::run_manifest_path(
        state_dir, run_uuid,
    ))
    .unwrap();
    assert!(manifest.contains("snapshot_signature_scheme="));
    assert!(state.process_tree.get_run(run_uuid).is_some());
}

#[cfg(feature = "test-signer")]
#[test]
fn publish_signed_snapshot_rejects_run_uuid_mismatch() {
    let tmp = TempDir::new().unwrap();
    let state_dir = tmp.path();
    let (input, bytes, signature) = signed_snapshot_request("actual-run");
    let state = daemon_state_for_publish(state_dir, &input, &signature, true);
    let reply = handle_publish_signed_snapshot_full(
        &state,
        guard_ipc::PublishSignedSnapshot::new("claimed-run", bytes, signature, false, false),
    );
    assert!(
        matches!(reply, guard_ipc::SnapshotReply::Err { message, .. } if message.contains("not prepared") || message.contains("run_uuid mismatch"))
    );
}

#[cfg(feature = "test-signer")]
#[test]
fn publish_signed_snapshot_rejects_signature_over_different_bytes() {
    let tmp = TempDir::new().unwrap();
    let state_dir = tmp.path();
    let run_uuid = "signed-publish-tampered";
    let (input, mut bytes, signature) = signed_snapshot_request(run_uuid);
    let state = daemon_state_for_publish(state_dir, &input, &signature, true);
    let last = bytes.last_mut().unwrap();
    *last ^= 0x01;
    let reply = handle_publish_signed_snapshot_full(
        &state,
        guard_ipc::PublishSignedSnapshot::new(run_uuid, bytes, signature, false, false),
    );
    match reply {
        guard_ipc::SnapshotReply::Err { message, .. } => assert!(
            message.contains("signed snapshot bytes do not match daemon-issued inputs")
                || message.contains("decode signed snapshot")
                || message.contains("snapshot signature verification failed")
                || message.contains("run_uuid mismatch"),
            "unexpected error: {message}"
        ),
        other => panic!("expected tamper rejection, got {other:?}"),
    }
}

#[cfg(feature = "test-signer")]
#[test]
fn publish_signed_snapshot_rejects_untrusted_signer() {
    let tmp = TempDir::new().unwrap();
    let state_dir = tmp.path();
    let run_uuid = "signed-publish-untrusted";
    let (input, bytes, signature) = signed_snapshot_request(run_uuid);
    let state = daemon_state_for_publish(state_dir, &input, &signature, false);
    let reply = handle_publish_signed_snapshot_full(
        &state,
        guard_ipc::PublishSignedSnapshot::new(run_uuid, bytes, signature, false, false),
    );
    assert!(
        matches!(reply, guard_ipc::SnapshotReply::Err { message, .. } if message.contains("not trusted"))
    );
}
