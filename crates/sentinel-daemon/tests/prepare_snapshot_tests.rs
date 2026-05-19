use sentinel_core::{AllowlistEntry, MatchType, RuleKind, RuleTier, SCHEMA_V2};
use sentinel_daemon::feed::store::{FeedIocRow, FeedStore};
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

    // Use the temp dir as cwd.
    let cwd = tmp.path().to_path_buf();
    let reply = handle_prepare_snapshot(&cwd, &curated, &rs, &pt, &state_dir, false, false);

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
    let reply = handle_prepare_snapshot(tmp.path(), &curated, &rs, &pt, &state_dir, false, false);
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

// ============================================================================
// v0.4 — V4 entry-point tests (fetch-pre-flight + FeedDeny merge). These
// exercise `handle_prepare_snapshot_v4_full` against a hand-rolled
// DaemonState whose `feed_store` is in-memory and whose
// `feed_fetch_mutex` / `last_fetch_result` are fresh (no concurrent fetch
// pressure). The real `fetch_feeds_blocking` would attempt to clone the OSV
// + GHSA repos against the network — these tests bypass that by hard-coding
// `SENTINEL_FEED_URL_OVERRIDE_*` to a file:// fixture URL when needed.
//
// For tests that don't need actual fetching, they assert deterministic
// behaviors (FeedDeny merge, tier ordering) by pre-populating the in-memory
// feed store and exercising the per-handler logic surface that isn't
// dependent on network. The fetch step requires a cloneable git URL; when
// tests don't provide one they expect the daemon to surface the fetch error
// as a strict-fail.
// ============================================================================

use sentinel_daemon::baseline_staging::BaselineStaging;
use sentinel_daemon::gap_detector::GapDetector;
use sentinel_daemon::handlers::prepare_snapshot::{
    handle_prepare_snapshot_inner_for_tests, handle_prepare_snapshot_v4_full,
};
use sentinel_daemon::install_artifacts::InstallArtifactStore;
use sentinel_daemon::ipc_server::{DaemonState, DeferredResolveTable};
use sentinel_daemon::log_writer::LogWriter;
use sentinel_daemon::prompt::{PromptDedup, RecentGapsRing};

fn build_daemon_state(state_dir: &std::path::Path) -> Arc<DaemonState> {
    sentinel_daemon::state_dir::ensure_runs_dir(state_dir).unwrap();
    let process_tree = Arc::new(ProcessTree::new());
    let gap_detector = Arc::new(GapDetector::new());
    let rule_store =
        Arc::new(RuleStore::open(&sentinel_daemon::state_dir::db_path(state_dir)).unwrap());
    let curated: Arc<Vec<AllowlistEntry>> = Arc::new(Vec::new());
    let install_artifact_store = Arc::new(InstallArtifactStore::open_in_memory().unwrap());
    let log_writer = LogWriter::noop();
    let prompt_dedup = Arc::new(PromptDedup::new());
    let recent_gaps = Arc::new(RecentGapsRing::new());
    let baseline_staging = Arc::new(BaselineStaging::new());
    // Open a feed_store against the same DB the rule_store migrated.
    let feed_store = Arc::new(
        FeedStore::open(&sentinel_daemon::state_dir::db_path(state_dir)).unwrap(),
    );
    let feed_fetch_mutex = Arc::new(std::sync::Mutex::new(()));
    let last_fetch_result = Arc::new(std::sync::RwLock::new(None));
    Arc::new(DaemonState {
        process_tree,
        gap_detector,
        rule_store,
        curated,
        state_dir: state_dir.to_path_buf(),
        install_artifact_store,
        log_writer,
        prompt_dedup,
        recent_gaps,
        baseline_staging,
        last_snapshot_publish_failed: std::sync::atomic::AtomicBool::new(false),
        deferred_resolve: Arc::new(DeferredResolveTable::new()),
        feed_store,
        feed_fetch_mutex,
        last_fetch_result,
        startup_instant: std::time::Instant::now(),
    })
}

/// Pre-prime `last_fetch_result` with a fresh "Ok" outcome so the next call to
/// `fetch_feeds_blocking` short-circuits via the shared-result path
/// (avoids the real network fetch in tests).
fn prime_shared_result_ok(state: &Arc<DaemonState>) {
    let mut w = state.last_fetch_result.write().unwrap();
    *w = Some(sentinel_daemon::feed::concurrency::LastFetchResult {
        completed_at: std::time::Instant::now(),
        outcome: Ok(Vec::new()),
    });
}

/// Pre-prime `last_fetch_result` with a fresh "Err" outcome to exercise the
/// strict-fail path without involving the network.
fn prime_shared_result_err(state: &Arc<DaemonState>) {
    let mut w = state.last_fetch_result.write().unwrap();
    *w = Some(sentinel_daemon::feed::concurrency::LastFetchResult {
        completed_at: std::time::Instant::now(),
        outcome: Err(sentinel_daemon::feed::concurrency::FeedFetchErrorSnapshot {
            kind: sentinel_daemon::feed::concurrency::FeedFetchErrorKind::Git,
            feed: "OSV".to_string(),
            message: "synthetic test failure".to_string(),
        }),
    });
}

fn host_ioc_row(advisory: &str, host: &str) -> FeedIocRow {
    FeedIocRow {
        feed: "OSV".to_string(),
        advisory_id: advisory.to_string(),
        ecosystem: String::new(),
        package: String::new(),
        versions_json: "{\"versions\":[],\"ranges\":[]}".to_string(),
        severity: None,
        tag: None,
        first_seen_ms: 0,
        host_ioc: Some(host.to_string()),
        schema_version_observed: "1.7.4".to_string(),
    }
}

#[test]
fn prepare_snapshot_v4_strict_fails_when_fetch_errors() {
    let tmp = TempDir::new().unwrap();
    let state = build_daemon_state(tmp.path());
    // Prime the cached result with an Err so the fetch_feeds_blocking call
    // surfaces it without touching the network.
    prime_shared_result_err(&state);

    let reply = handle_prepare_snapshot_v4_full(&state, tmp.path(), false, false);
    match reply {
        sentinel_ipc::SnapshotReply::Err { message, .. } => {
            assert!(
                message.starts_with("feed fetch:"),
                "expected strict-fail message prefix; got {message}"
            );
        }
        sentinel_ipc::SnapshotReply::Ok { .. } => {
            panic!("expected Err under primed Err shared-result");
        }
    }
}

#[test]
fn prepare_snapshot_v4_merges_feeddeny_after_successful_fetch() {
    let tmp = TempDir::new().unwrap();
    let state = build_daemon_state(tmp.path());
    // Pre-populate the feed store with three host IoCs covering all three
    // classify_host branches (Exact, Suffix, Ip).
    state
        .feed_store
        .upsert_iocs(&[
            host_ioc_row("MAL-2026-A", "evil.example.com"),
            host_ioc_row("MAL-2026-B", "192.0.2.1"),
            host_ioc_row("MAL-2026-C", "*.workers.dev"),
        ])
        .unwrap();
    // Prime the shared-result cache with Ok so fetch_feeds_blocking
    // short-circuits cleanly. With no pending feed_warnings, the SnapshotReply
    // should be ok_v4 with feed_warnings empty.
    prime_shared_result_ok(&state);

    let reply = handle_prepare_snapshot_v4_full(&state, tmp.path(), false, false);
    let run_uuid = match reply {
        sentinel_ipc::SnapshotReply::Ok {
            run_uuid,
            schema_version,
            feed_warnings,
            ..
        } => {
            // V4 schema_version + empty warnings (cached fetch had no warnings).
            assert_eq!(schema_version, sentinel_ipc::IPC_SCHEMA_V4);
            assert!(feed_warnings.is_empty());
            run_uuid
        }
        sentinel_ipc::SnapshotReply::Err { message, .. } => {
            panic!("expected Ok; got Err: {message}");
        }
    };

    let snap_path =
        sentinel_daemon::state_dir::run_snapshot_path(tmp.path(), &run_uuid);
    let bytes = std::fs::read(&snap_path).unwrap();
    let snap = sentinel_core::Snapshot::decode(&bytes).expect("decode");

    let feeddeny_count = snap
        .entries
        .iter()
        .filter(|e| matches!(e.tier, RuleTier::FeedDeny))
        .count();
    assert_eq!(
        feeddeny_count, 3,
        "expected 3 FeedDeny entries from the 3 seeded host_iocs; got {feeddeny_count}"
    );

    let kinds: Vec<MatchType> = snap
        .entries
        .iter()
        .filter(|e| matches!(e.tier, RuleTier::FeedDeny))
        .map(|e| e.match_type)
        .collect();
    assert!(kinds.iter().any(|k| matches!(k, MatchType::Exact)));
    assert!(kinds.iter().any(|k| matches!(k, MatchType::Suffix)));
    assert!(kinds.iter().any(|k| matches!(k, MatchType::Ip)));
}

#[test]
fn prepare_snapshot_v4_curated_allow_beats_feeddeny_in_sorted_snapshot() {
    let tmp = TempDir::new().unwrap();
    let state = build_daemon_state(tmp.path());
    // The structural tier-ordering invariant: a feed-derived FeedDeny for
    // registry.npmjs.org must NOT come before the curated allow.
    state
        .feed_store
        .upsert_iocs(&[host_ioc_row("MAL-2026-NPM", "registry.npmjs.org")])
        .unwrap();
    prime_shared_result_ok(&state);

    // Inject a curated CuratedAllow for registry.npmjs.org via test seam.
    let curated = vec![AllowlistEntry {
        kind: RuleKind::Allow,
        tier: RuleTier::CuratedAllow,
        match_type: MatchType::Exact,
        pattern: "registry.npmjs.org".to_string(),
        reason: "npm registry".to_string(),
    }];
    let reply = handle_prepare_snapshot_inner_for_tests(
        tmp.path(),
        &curated,
        &state.rule_store,
        &state.process_tree,
        tmp.path(),
        false,
        false,
        Some(&state.feed_store),
        Some(&state.feed_fetch_mutex),
        Some(&state.last_fetch_result),
    );
    let run_uuid = match reply {
        sentinel_ipc::SnapshotReply::Ok { run_uuid, .. } => run_uuid,
        other => panic!("expected Ok; got {other:?}"),
    };
    let snap_path =
        sentinel_daemon::state_dir::run_snapshot_path(tmp.path(), &run_uuid);
    let bytes = std::fs::read(&snap_path).unwrap();
    let snap = sentinel_core::Snapshot::decode(&bytes).expect("decode");

    // Find both the curated-allow entry and the feed-deny entry for
    // registry.npmjs.org. The curated entry must come FIRST (CuratedAllow=1
    // < FeedDeny=4 in the sorted list).
    let curated_idx = snap
        .entries
        .iter()
        .position(|e| {
            matches!(e.tier, RuleTier::CuratedAllow) && e.pattern == "registry.npmjs.org"
        })
        .expect("curated allow for registry.npmjs.org");
    let feed_idx = snap
        .entries
        .iter()
        .position(|e| {
            matches!(e.tier, RuleTier::FeedDeny) && e.pattern == "registry.npmjs.org"
        })
        .expect("feed deny for registry.npmjs.org");
    assert!(
        curated_idx < feed_idx,
        "curated allow must come before feed deny in sorted snapshot \
         (curated_idx={curated_idx}, feed_idx={feed_idx})"
    );
}
