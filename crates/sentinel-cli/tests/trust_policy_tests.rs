//! End-to-end tests for `sentinel trust-policy <path>` IPC client + the
//! `prepare_snapshot` pre-spawn IPC. These mirror the round-trip pattern of
//! `spawn_envp_tests::register_root_with_daemon_round_trips_ack` — spin up a
//! real daemon's `IpcServer::accept_one` and send the new tagged frames.
//!
//! Plan 02-06b (CLI side; the daemon-side handlers are in plan 02-06a).

use sentinel_cli::ipc_client::{prepare_snapshot, trust_policy_request};
use sentinel_daemon::gap_detector::GapDetector;
use sentinel_daemon::ipc_server::{DaemonState, IpcServer};
use sentinel_daemon::rule_store::RuleStore;
use sentinel_daemon::state_dir::{db_path, ensure_runs_dir, ensure_state_dir, socket_path};
use sentinel_daemon::tracked::ProcessTree;
use sha2::Digest;
use std::path::Path;
use std::sync::Arc;
use std::thread;

fn build_state(state_dir: &Path) -> Arc<DaemonState> {
    let tree = Arc::new(ProcessTree::new());
    let det = Arc::new(GapDetector::new());
    let rs = Arc::new(RuleStore::open(&db_path(state_dir)).expect("open rule store"));
    let curated = Arc::new(Vec::new());
    Arc::new(DaemonState::new(tree, det, rs, curated, state_dir.to_path_buf()))
}

#[test]
fn prepare_snapshot_round_trips_against_live_daemon() {
    let tmp = tempfile::tempdir().unwrap();
    ensure_state_dir(tmp.path()).unwrap();
    ensure_runs_dir(tmp.path()).unwrap();
    let sock = socket_path(tmp.path());
    let state = build_state(tmp.path());
    let server = IpcServer::bind(&sock, state).expect("bind");

    let h = thread::spawn(move || {
        server.accept_one().expect("accept_one");
    });

    // The CLI sends its current working directory; the daemon responds with a
    // freshly-published per-run snapshot. We pass the tempdir as the cwd so the
    // daemon won't find any .sentinel.toml above it.
    let cwd = tmp.path();
    let r = prepare_snapshot(&sock, cwd);
    h.join().unwrap();

    let (manifest_path, run_uuid) = r.expect("prepare_snapshot Ok");
    assert!(manifest_path.exists(), "manifest must be written: {}", manifest_path.display());
    assert!(!run_uuid.is_empty(), "run_uuid must be a UUID string");
    // UUID v4 is 36 chars (8-4-4-4-12 with hyphens)
    assert_eq!(run_uuid.len(), 36, "UUID v4 string is 36 chars: got {run_uuid:?}");
}

#[test]
fn trust_policy_request_round_trips_against_live_daemon() {
    let tmp = tempfile::tempdir().unwrap();
    ensure_state_dir(tmp.path()).unwrap();
    let sock = socket_path(tmp.path());
    let state = build_state(tmp.path());
    let server = IpcServer::bind(&sock, state).expect("bind");

    // Write a real .sentinel.toml inside the tempdir so the daemon-side
    // re-hash matches what we send.
    let toml_path = tmp.path().join(".sentinel.toml");
    let body = "version = 1\n\n[[rules]]\nkind = \"allow\"\nmatch = \"exact\"\npattern = \"example.com\"\nreason = \"test\"\n";
    std::fs::write(&toml_path, body).unwrap();
    let sha = format!("{:x}", sha2::Sha256::digest(body.as_bytes()));

    let h = thread::spawn(move || {
        server.accept_one().expect("accept_one");
    });

    let r = trust_policy_request(&sock, &toml_path.display().to_string(), &sha);
    h.join().unwrap();
    r.expect("trust_policy_request Ok");
}
