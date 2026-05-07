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
use std::sync::{Arc, Mutex};
use std::thread;

/// WR-07 fix: serialize tests in this file that mutate
/// `SENTINEL_SKIP_FEED_FETCH`. Cargo runs tests within one crate in
/// parallel by default; without serialization, a sibling test that
/// expects the env var unset can transiently observe it set (and vice
/// versa) depending on thread scheduling. Today only
/// `prepare_snapshot_round_trips_against_live_daemon` mutates it, but
/// any future test that adds an env-var dance gets serialization for
/// free.
static ENV_TEST_GUARD: Mutex<()> = Mutex::new(());

/// Drop guard that restores `SENTINEL_SKIP_FEED_FETCH` to its prior
/// state when scope ends. Runs even on assertion panic (cargo test
/// forces panic = unwind regardless of the workspace's panic = abort
/// profile setting).
struct SkipFeedFetchGuard {
    prior: Option<std::ffi::OsString>,
}

impl SkipFeedFetchGuard {
    fn set() -> Self {
        let prior = std::env::var_os("SENTINEL_SKIP_FEED_FETCH");
        // SAFETY: `set_var` is unsafe in Rust 2024. We hold ENV_TEST_GUARD
        // for the lifetime of this guard so concurrent reads from sibling
        // tests in this file are serialized; for sibling tests in OTHER
        // crates (which run in separate processes) cargo gives us
        // process-isolation by default.
        unsafe {
            std::env::set_var("SENTINEL_SKIP_FEED_FETCH", "1");
        }
        Self { prior }
    }
}

impl Drop for SkipFeedFetchGuard {
    fn drop(&mut self) {
        // SAFETY: same as set() above — ENV_TEST_GUARD serializes mutation.
        unsafe {
            match self.prior.take() {
                Some(v) => std::env::set_var("SENTINEL_SKIP_FEED_FETCH", v),
                None => std::env::remove_var("SENTINEL_SKIP_FEED_FETCH"),
            }
        }
    }
}

fn build_state(state_dir: &Path) -> Arc<DaemonState> {
    let tree = Arc::new(ProcessTree::new());
    let det = Arc::new(GapDetector::new());
    let rs = Arc::new(RuleStore::open(&db_path(state_dir)).expect("open rule store"));
    let curated = Arc::new(Vec::new());
    Arc::new(DaemonState::new(tree, det, rs, curated, state_dir.to_path_buf()))
}

#[test]
fn prepare_snapshot_round_trips_against_live_daemon() {
    // Phase 4 plan 04-03: the daemon's PrepareSnapshot now pre-flights a feed
    // fetch (D-83). This Phase 2 round-trip test runs in-process and has no
    // git fixture; we set SENTINEL_SKIP_FEED_FETCH=1 to short-circuit the
    // fetch with an empty Ok outcome.
    //
    // WR-07 fix: serialize this test (which mutates env) against any sibling
    // test in this file via ENV_TEST_GUARD, AND scope-guard the env-var
    // lifetime so a panic mid-test still restores the prior value.
    let _serial = ENV_TEST_GUARD
        .lock()
        .unwrap_or_else(|p| p.into_inner());
    let _skip = SkipFeedFetchGuard::set();

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

    // _skip's Drop restores SENTINEL_SKIP_FEED_FETCH to its prior state.
    // _serial's Drop releases ENV_TEST_GUARD so a sibling test can run.
}

#[test]
fn trust_policy_request_round_trips_against_live_daemon() {
    // WR-07 defense-in-depth: serialize against the env-mutating sibling
    // test. This test does NOT itself mutate SENTINEL_SKIP_FEED_FETCH,
    // but the daemon thread we spin up reads the env var transitively
    // (via DaemonState's wired feed primitives). Without serialization, a
    // racing `prepare_snapshot_round_trips_against_live_daemon` could
    // toggle the env var mid-flight.
    let _serial = ENV_TEST_GUARD
        .lock()
        .unwrap_or_else(|p| p.into_inner());

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

    // BLOCKER-03: daemon canonicalizes and rejects non-canonical wire input.
    // macOS resolves `/var/folders/...` through a symlink to
    // `/private/var/folders/...`. The CLI's real `run_trust_policy` path
    // canonicalizes before sending; this lower-level `trust_policy_request`
    // test must canonicalize explicitly.
    let canonical = toml_path
        .canonicalize()
        .expect("canonicalize")
        .display()
        .to_string();

    let h = thread::spawn(move || {
        server.accept_one().expect("accept_one");
    });

    let r = trust_policy_request(&sock, &canonical, &sha);
    h.join().unwrap();
    r.expect("trust_policy_request Ok");
}
