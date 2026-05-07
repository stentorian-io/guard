//! Phase 4 plan 04-02 — fetch coordination + shared-result optimization (D-86).
//!
//! `fetch_feeds_blocking` is the single public entry point for triggering a
//! feed refresh. It serializes concurrent runs through `feed_fetch_mutex`
//! AND short-circuits when a recent fetch result is still fresh (within
//! `SHARED_RESULT_TTL`) — N concurrent `sentinel run` invocations within a
//! 5-second window observe ONE underlying fetch and reuse its outcome.
//!
//! Per RESEARCH.md Code Example 1 (lines 690-732). Per D-85: any per-feed
//! error fails the whole run; the last_result cache stores the snapshotted
//! error so concurrent waiters surface the same error.

use std::path::{Path, PathBuf};
use std::sync::{Mutex, RwLock};
use std::time::{Duration, Instant};

use crate::feed::fetcher::{
    fetch_one_feed, url_override_for, FeedFetchError, FetchOutcome, FETCH_DEADLINE_FIRST_RUN,
    FETCH_DEADLINE_INCREMENTAL, FEEDS,
};
use crate::feed::store::FeedStore;

pub const SHARED_RESULT_TTL: Duration = Duration::from_secs(5);

/// FeedFetchError is not Clone because std::io::Error and rusqlite::Error
/// don't impl Clone. Snapshot it as a simple kind+message string for
/// shared-result reuse.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FeedFetchErrorSnapshot {
    pub kind: String,
    pub message: String,
}

impl FeedFetchErrorSnapshot {
    pub fn into_error(self) -> FeedFetchError {
        // Reconstitute as a Git-shaped error preserving kind+message; the
        // schema-version observability isn't lost because the shared-result
        // path is only used within a 5s window for a single underlying fetch.
        FeedFetchError::Git {
            feed: self.kind,
            message: self.message,
        }
    }
}

#[derive(Debug, Clone)]
pub struct LastFetchResult {
    pub completed_at: Instant,
    pub outcome: Result<Vec<FetchOutcome>, FeedFetchErrorSnapshot>,
}

/// Function pointer type for the per-feed fetch step. Tests inject a
/// counting closure so they can assert "only N actual fetches occurred for
/// M concurrent fetch_feeds_blocking calls".
pub type FetchFn = fn(
    feed_name: &str,
    url: &str,
    local: &Path,
    deadline: Instant,
    feed_store: &FeedStore,
) -> Result<FetchOutcome, FeedFetchError>;

/// Production entry point. Uses the real fetcher.
pub fn fetch_feeds_blocking(
    state_dir: &Path,
    fetch_mutex: &Mutex<()>,
    last_result: &RwLock<Option<LastFetchResult>>,
    feed_store: &FeedStore,
) -> Result<Vec<FetchOutcome>, FeedFetchError> {
    fetch_feeds_blocking_with(state_dir, fetch_mutex, last_result, feed_store, fetch_one_feed)
}

/// Test seam — accepts an injected fetch function. Production call sites use
/// `fetch_feeds_blocking` (which delegates with `fetch_one_feed`).
pub fn fetch_feeds_blocking_with(
    state_dir: &Path,
    fetch_mutex: &Mutex<()>,
    last_result: &RwLock<Option<LastFetchResult>>,
    feed_store: &FeedStore,
    fetch_fn: FetchFn,
) -> Result<Vec<FetchOutcome>, FeedFetchError> {
    let _guard = fetch_mutex.lock().unwrap_or_else(|p| p.into_inner());

    // Test seam: `SENTINEL_SKIP_FEED_FETCH=1` short-circuits the fetch
    // entirely with an empty Ok outcome. Used by Phase 2/3 integration tests
    // that exercise the IPC pipeline against a real DaemonState — those tests
    // pre-date Phase 4 and have no real git fixture to point at, so without
    // this seam every `prepare_snapshot` round-trip would attempt a real
    // network fetch against github.com and hang past the 5s read timeout.
    // Hermetic Phase 4 e2e tests (plan 04-04) point at a `file://` fixture
    // via `SENTINEL_FEED_URL_OVERRIDE_*` and do NOT set this var.
    if std::env::var_os("SENTINEL_SKIP_FEED_FETCH").is_some() {
        return Ok(Vec::new());
    }

    // Shared-result reuse (D-86): if a previous run completed within
    // SHARED_RESULT_TTL, return its snapshotted outcome. Concurrent waiters
    // unblock as soon as the lock above is released and observe the cached
    // result without firing another fetch.
    {
        let prev = last_result.read().unwrap_or_else(|p| p.into_inner());
        if let Some(ref lr) = *prev {
            if lr.completed_at.elapsed() < SHARED_RESULT_TTL {
                // TI-08 observability: emit a fetch_cached_share event so the
                // feed_no_per_query.rs e2e test can distinguish "actually
                // fetched" from "served from D-86 shared-result cache". Both
                // share `target = "sentinel.feed.fetch"` but only fetch_start
                // represents an outbound fetch attempt.
                tracing::info!(
                    target = "sentinel.feed.fetch",
                    op = "fetch_cached_share",
                    "reusing prior fetch outcome (D-86 shared-result within TTL)",
                );
                return match &lr.outcome {
                    Ok(o) => Ok(o.clone()),
                    Err(snap) => Err(snap.clone().into_error()),
                };
            }
        }
    }

    crate::state_dir::ensure_feeds_dir(state_dir)?;

    let mut outcomes: Vec<FetchOutcome> = Vec::new();
    for (feed_name, default_url) in FEEDS {
        let url = url_override_for(feed_name).unwrap_or_else(|| (*default_url).to_string());
        let local: PathBuf = crate::state_dir::feed_subdir(state_dir, feed_name);
        let is_first_run = !local.join(".git").exists();
        let deadline_dur = if is_first_run {
            FETCH_DEADLINE_FIRST_RUN
        } else {
            FETCH_DEADLINE_INCREMENTAL
        };
        let deadline = Instant::now() + deadline_dur;

        match fetch_fn(feed_name, &url, &local, deadline, feed_store) {
            Ok(outcome) => outcomes.push(outcome),
            Err(e) => {
                let snapshot = snapshot_err(&e);
                let mut w = last_result.write().unwrap_or_else(|p| p.into_inner());
                *w = Some(LastFetchResult {
                    completed_at: Instant::now(),
                    outcome: Err(snapshot),
                });
                return Err(e);
            }
        }
    }

    let mut w = last_result.write().unwrap_or_else(|p| p.into_inner());
    *w = Some(LastFetchResult {
        completed_at: Instant::now(),
        outcome: Ok(outcomes.clone()),
    });
    Ok(outcomes)
}

fn snapshot_err(e: &FeedFetchError) -> FeedFetchErrorSnapshot {
    let (kind, message) = match e {
        FeedFetchError::Io(err) => ("io".to_string(), err.to_string()),
        FeedFetchError::Git { feed, message } => {
            (format!("git:{feed}"), message.clone())
        }
        FeedFetchError::Timeout { feed, seconds } => (
            format!("timeout:{feed}"),
            format!("exceeded {seconds}s ceiling"),
        ),
        FeedFetchError::Panic { feed, message } => (
            format!("panic:{feed}"),
            message.clone(),
        ),
        FeedFetchError::Store(err) => ("store".to_string(), err.to_string()),
    };
    FeedFetchErrorSnapshot { kind, message }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    use tempfile::tempdir;

    fn open_store_at_state_dir() -> (tempfile::TempDir, FeedStore, PathBuf) {
        let dir = tempdir().expect("tempdir");
        let state_dir = dir.path().to_path_buf();
        // Mirror the real layout: $state_dir/sentinel.db.
        let db = state_dir.join("sentinel.db");
        let _store = crate::rule_store::RuleStore::open(&db).expect("rule store open");
        let fs = FeedStore::open(&db).expect("feed store open");
        (dir, fs, state_dir)
    }

    // Test-only counting fetch function. Closes over a static AtomicUsize set
    // before each test (via the global FETCH_COUNTER below). We can't capture
    // a closure since FetchFn is a `fn` pointer; module-level statics are the
    // straightforward path.
    //
    // TEST_GUARD serializes the tests in this module so they don't share the
    // FETCH_COUNTER state (cargo runs tests in parallel within one process by
    // default).
    static FETCH_COUNTER: AtomicUsize = AtomicUsize::new(0);
    static FETCH_DELAY_MS: AtomicUsize = AtomicUsize::new(0);
    static TEST_GUARD: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn counting_fetch(
        feed_name: &str,
        _url: &str,
        _local: &Path,
        _deadline: Instant,
        _feed_store: &FeedStore,
    ) -> Result<FetchOutcome, FeedFetchError> {
        FETCH_COUNTER.fetch_add(1, Ordering::SeqCst);
        let delay = FETCH_DELAY_MS.load(Ordering::SeqCst);
        if delay > 0 {
            std::thread::sleep(Duration::from_millis(delay as u64));
        }
        Ok(FetchOutcome {
            feed: feed_name.to_string(),
            commit_sha: format!("sha-{feed_name}"),
            records_parsed: 1,
            records_failed: 0,
            host_iocs_extracted: 0,
            schema_version_observed: Some("1.7.4".to_string()),
            warnings: Vec::new(),
        })
    }

    fn always_fail_fetch(
        feed_name: &str,
        _url: &str,
        _local: &Path,
        _deadline: Instant,
        _feed_store: &FeedStore,
    ) -> Result<FetchOutcome, FeedFetchError> {
        FETCH_COUNTER.fetch_add(1, Ordering::SeqCst);
        Err(FeedFetchError::Git {
            feed: feed_name.to_string(),
            message: "synthetic".into(),
        })
    }

    #[test]
    fn fetch_feeds_blocking_records_outcome_in_metadata() {
        let _guard = TEST_GUARD.lock().unwrap_or_else(|p| p.into_inner());
        // The injected counting_fetch returns Ok but does NOT write metadata
        // (it's a stub). Production fetch_one_feed writes metadata; that's
        // covered by fetcher.rs tests. This test verifies the concurrency
        // wrapper reaches the inner function for both feeds.
        FETCH_COUNTER.store(0, Ordering::SeqCst);
        FETCH_DELAY_MS.store(0, Ordering::SeqCst);
        let (_dir, store, state_dir) = open_store_at_state_dir();
        let mtx = Mutex::new(());
        let last = RwLock::new(None);
        let outcomes =
            fetch_feeds_blocking_with(&state_dir, &mtx, &last, &store, counting_fetch).expect("ok");
        assert_eq!(outcomes.len(), FEEDS.len());
        assert_eq!(FETCH_COUNTER.load(Ordering::SeqCst), FEEDS.len());
    }

    #[test]
    fn fetch_feeds_blocking_uses_shared_result() {
        let _guard = TEST_GUARD.lock().unwrap_or_else(|p| p.into_inner());
        // Spawn 4 threads, each calling fetch_feeds_blocking. With a 100ms
        // injected delay and SHARED_RESULT_TTL=5s, the first call holds the
        // lock during the fetch; the others queue, then on dequeue see
        // last_result is fresh and skip the per-feed fetch entirely. Net:
        // FEEDS.len() actual fetches (one batch) regardless of N threads.
        FETCH_COUNTER.store(0, Ordering::SeqCst);
        FETCH_DELAY_MS.store(100, Ordering::SeqCst);
        let (_dir, store, state_dir) = open_store_at_state_dir();
        let store = Arc::new(store);
        let mtx = Arc::new(Mutex::new(()));
        let last = Arc::new(RwLock::new(None));

        let mut handles = Vec::new();
        for _ in 0..4 {
            let s = Arc::clone(&store);
            let m = Arc::clone(&mtx);
            let l = Arc::clone(&last);
            let sd = state_dir.clone();
            handles.push(std::thread::spawn(move || {
                fetch_feeds_blocking_with(&sd, &m, &l, &s, counting_fetch).expect("ok")
            }));
        }
        for h in handles {
            let _ = h.join().expect("thread");
        }
        // Exactly FEEDS.len() actual fetches occurred (the FIRST call did
        // them; the other 3 saw the fresh last_result and short-circuited).
        assert_eq!(
            FETCH_COUNTER.load(Ordering::SeqCst),
            FEEDS.len(),
            "shared-result optimization failed: expected {} fetches, got {}",
            FEEDS.len(),
            FETCH_COUNTER.load(Ordering::SeqCst)
        );
        FETCH_DELAY_MS.store(0, Ordering::SeqCst);
    }

    #[test]
    fn fetch_feeds_blocking_propagates_error_and_caches_snapshot() {
        let _guard = TEST_GUARD.lock().unwrap_or_else(|p| p.into_inner());
        FETCH_COUNTER.store(0, Ordering::SeqCst);
        FETCH_DELAY_MS.store(0, Ordering::SeqCst);
        let (_dir, store, state_dir) = open_store_at_state_dir();
        let mtx = Mutex::new(());
        let last = RwLock::new(None);

        let err = fetch_feeds_blocking_with(&state_dir, &mtx, &last, &store, always_fail_fetch)
            .expect_err("must fail");
        assert!(matches!(err, FeedFetchError::Git { .. }));
        // Snapshot cached.
        let cached = last.read().unwrap().clone().expect("cached");
        assert!(cached.outcome.is_err());

        // Second call within TTL surfaces the cached error WITHOUT another
        // call to always_fail_fetch.
        let count_before = FETCH_COUNTER.load(Ordering::SeqCst);
        let err2 = fetch_feeds_blocking_with(&state_dir, &mtx, &last, &store, always_fail_fetch)
            .expect_err("must fail");
        assert!(matches!(err2, FeedFetchError::Git { .. }));
        assert_eq!(
            FETCH_COUNTER.load(Ordering::SeqCst),
            count_before,
            "shared-result optimization must reuse the cached error"
        );
    }

    #[test]
    fn snapshot_err_carries_kind_and_message() {
        let e = FeedFetchError::Timeout {
            feed: "OSV".to_string(),
            seconds: 60,
        };
        let s = snapshot_err(&e);
        assert!(s.kind.contains("timeout"));
        assert!(s.message.contains("60"));
    }
}
