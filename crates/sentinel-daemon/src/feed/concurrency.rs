//! v0.4 — fetch coordination + shared-result optimization.
//!
//! `fetch_feeds_blocking` is the single public entry point for triggering a
//! feed refresh. It serializes concurrent runs through `feed_fetch_mutex`
//! AND short-circuits when a recent fetch result is still fresh (within
//! `SHARED_RESULT_TTL`) — N concurrent `sentinel wrap` invocations within a
//! 5-second window observe ONE underlying fetch and reuse its outcome.
//!
//! Per RESEARCH.md Code Example 1 (lines 690-732). Any per-feed
//! error fails the whole run; the last_result cache stores the snapshotted
//! error so concurrent waiters surface the same error.

use std::path::{Path, PathBuf};
use std::sync::{Mutex, RwLock};
#[cfg(any(test, debug_assertions))]
use std::sync::Once;
use std::time::{Duration, Instant};

use crate::feed::fetcher::{
    fetch_one_feed, url_override_for, FeedFetchError, FetchOutcome, FETCH_DEADLINE_FIRST_RUN,
    FETCH_DEADLINE_INCREMENTAL, FEEDS,
};
use crate::feed::store::FeedStore;

pub const SHARED_RESULT_TTL: Duration = Duration::from_secs(5);

/// FeedFetchError is not Clone because std::io::Error and rusqlite::Error
/// don't impl Clone. Snapshot it as a tagged variant + feed + message so
/// shared-result reuse reconstructs the SAME variant the original fetch
/// produced — preserves error-kind fidelity for downstream log greps and
/// `feed_metadata.error_message` attribution.
///
/// WR-01 fix: prior shape collapsed `kind: String` for every variant and
/// rebuilt every cached error as `FeedFetchError::Git { feed: kind,
/// message }`. A panic variant round-tripped as
/// `git (panic:OSV): <msg>`, mis-attributing a panic as a git failure
/// in any caller that wrote the reconstituted error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FeedFetchErrorKind {
    Io,
    Git,
    Timeout { seconds: u64 },
    Panic,
    Store,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FeedFetchErrorSnapshot {
    pub kind: FeedFetchErrorKind,
    pub feed: String,
    pub message: String,
}

impl FeedFetchErrorSnapshot {
    pub fn into_error(self) -> FeedFetchError {
        // WR-01: reconstruct faithfully so a cached panic surfaces as
        // FeedFetchError::Panic (not Git), a cached timeout as Timeout, etc.
        // Io and Store are slightly lossy (the original std::io::Error /
        // FeedStoreError carried richer context that doesn't serialize) — we
        // wrap as std::io::Error::other / FeedStoreError::Sql + InvalidQuery
        // proxy so the variant tag is preserved.
        match self.kind {
            FeedFetchErrorKind::Git => FeedFetchError::Git {
                feed: self.feed,
                message: self.message,
            },
            FeedFetchErrorKind::Panic => FeedFetchError::Panic {
                feed: self.feed,
                message: self.message,
            },
            FeedFetchErrorKind::Timeout { seconds } => FeedFetchError::Timeout {
                feed: self.feed,
                seconds,
            },
            FeedFetchErrorKind::Io => {
                FeedFetchError::Io(std::io::Error::other(self.message))
            }
            FeedFetchErrorKind::Store => FeedFetchError::Store(
                crate::feed::store::FeedStoreError::Sql(
                    rusqlite::Error::InvalidQuery,
                ),
            ),
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
///
/// WR-03 fix: `deadline_seconds: u64` parameter added so the inner fetch
/// can surface the ACTUAL applied deadline (60s incremental / 120s first-
/// run / e2e-fixture overrides) in `FeedFetchError::Timeout`, rather than
/// the previously hardcoded worst-case 120s.
pub type FetchFn = fn(
    feed_name: &str,
    url: &str,
    local: &Path,
    deadline: Instant,
    deadline_seconds: u64,
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

    // CR-02 fix: SENTINEL_SKIP_FEED_FETCH is a TEST-ONLY seam — it is
    // compile-time gated to non-release builds (`cfg(any(test,
    // debug_assertions))`) so a Homebrew-distributed release `sentineld`
    // CANNOT have feed enforcement disabled by setting an env var (e.g.
    // `launchctl setenv SENTINEL_SKIP_FEED_FETCH 1`). Even in non-release
    // builds we emit a once-per-process loud `tracing::warn!` so a
    // developer running tests is told the seam is active. This protects
    // the project's stated "core value" (block compromised packages
    // phoning home) from being silently disabled by environment.
    //
    // Production callers (sentineld release binary): the env var is a
    // no-op — feeds are always fetched.
    //
    // Test callers (v0.2/v0.3 in-process IPC tests, sentinel-e2e
    // DaemonHarness): cargo test runs in debug mode by default which
    // enables `debug_assertions`, so the seam works for them. Hermetic
    // v0.4 e2e tests explicitly OPT OUT of the skip and
    // point at a `file://` fixture via `SENTINEL_FEED_URL_OVERRIDE_*`.
    #[cfg(any(test, debug_assertions))]
    {
        if std::env::var_os("SENTINEL_SKIP_FEED_FETCH").is_some() {
            log_skip_feed_fetch_warning_once();
            return Ok(Vec::new());
        }
    }

    // Shared-result reuse: if a previous run completed within
    // SHARED_RESULT_TTL, return its snapshotted outcome. Concurrent waiters
    // unblock as soon as the lock above is released and observe the cached
    // result without firing another fetch.
    {
        let prev = last_result.read().unwrap_or_else(|p| p.into_inner());
        if let Some(ref lr) = *prev {
            if lr.completed_at.elapsed() < SHARED_RESULT_TTL {
                // TI-08 observability: emit a fetch_cached_share event so the
                // feed_no_per_query.rs e2e test can distinguish "actually
                // fetched" from "served from shared-result cache". Both
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
        // WR-03 fix: pass the ACTUAL chosen deadline-seconds value alongside
        // the Instant so the fetcher's Timeout errors report the real
        // ceiling (60 vs 120) instead of always-120.
        let deadline_seconds = deadline_dur.as_secs();
        let deadline = Instant::now() + deadline_dur;

        match fetch_fn(feed_name, &url, &local, deadline, deadline_seconds, feed_store) {
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

/// CR-02 fix: emit a single loud structured warning the first time
/// `SENTINEL_SKIP_FEED_FETCH` is observed in this process. The seam is
/// already compile-time-gated to non-release builds (so a release
/// daemon never reaches this function), but even in test/debug mode we
/// want the developer to know they have temporarily disabled feed
/// enforcement — silent disablement is the foot-gun the original
/// review flagged.
#[cfg(any(test, debug_assertions))]
fn log_skip_feed_fetch_warning_once() {
    static WARN_ONCE: Once = Once::new();
    WARN_ONCE.call_once(|| {
        tracing::warn!(
            target = "sentinel.feed.fetch",
            event = "feed_disabled_by_env",
            env_var = "SENTINEL_SKIP_FEED_FETCH",
            "FEED ENFORCEMENT DISABLED via SENTINEL_SKIP_FEED_FETCH \
             — this is a TEST-ONLY seam (release builds compile it \
             out). sentineld will NOT block compromised-package \
             threat-intel hosts while this env var is set."
        );
    });
}

fn snapshot_err(e: &FeedFetchError) -> FeedFetchErrorSnapshot {
    // WR-01 fix: tag the variant explicitly so `into_error` round-trips it
    // back to the SAME variant. Feed name + message ride alongside.
    match e {
        FeedFetchError::Io(err) => FeedFetchErrorSnapshot {
            kind: FeedFetchErrorKind::Io,
            feed: String::new(), // Io errors have no per-feed attribution
            message: err.to_string(),
        },
        FeedFetchError::Git { feed, message } => FeedFetchErrorSnapshot {
            kind: FeedFetchErrorKind::Git,
            feed: feed.clone(),
            message: message.clone(),
        },
        FeedFetchError::Timeout { feed, seconds } => FeedFetchErrorSnapshot {
            kind: FeedFetchErrorKind::Timeout { seconds: *seconds },
            feed: feed.clone(),
            message: format!("exceeded {seconds}s ceiling"),
        },
        FeedFetchError::Panic { feed, message } => FeedFetchErrorSnapshot {
            kind: FeedFetchErrorKind::Panic,
            feed: feed.clone(),
            message: message.clone(),
        },
        FeedFetchError::Store(err) => FeedFetchErrorSnapshot {
            kind: FeedFetchErrorKind::Store,
            feed: String::new(), // Store errors have no per-feed attribution
            message: err.to_string(),
        },
    }
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

    /// WR-06 fix: scope-guard that sets `FETCH_DELAY_MS` on construction
    /// and resets it to 0 on Drop. Without it, a panicking assertion
    /// between manual `FETCH_DELAY_MS.store(x)` and a manual reset
    /// would leak the delay into subsequent tests — TEST_GUARD's
    /// poisoned-mutex recovery (`unwrap_or_else(|p| p.into_inner())`)
    /// means a sibling test would acquire the mutex and observe the
    /// stale delay, slowing it or introducing timing flakes.
    struct DelayGuard;
    impl DelayGuard {
        fn set(ms: usize) -> Self {
            FETCH_DELAY_MS.store(ms, Ordering::SeqCst);
            Self
        }
    }
    impl Drop for DelayGuard {
        fn drop(&mut self) {
            FETCH_DELAY_MS.store(0, Ordering::SeqCst);
        }
    }

    fn counting_fetch(
        feed_name: &str,
        _url: &str,
        _local: &Path,
        _deadline: Instant,
        _deadline_seconds: u64,
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
        _deadline_seconds: u64,
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
        // WR-06 fix: scope-guard the FETCH_DELAY_MS mutation so it always
        // resets to 0 even on assertion panic. Previously the manual
        // `FETCH_DELAY_MS.store(0)` at the bottom of the test body would
        // be skipped if any prior assertion fired, leaking the delay
        // into sibling tests via the poisoned-lock recovery path.
        let _delay = DelayGuard::set(100);
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
        // _delay's Drop resets FETCH_DELAY_MS to 0 here.
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
        assert!(matches!(s.kind, FeedFetchErrorKind::Timeout { seconds: 60 }));
        assert_eq!(s.feed, "OSV");
        assert!(s.message.contains("60"));
    }

    #[test]
    fn snapshot_err_round_trip_preserves_panic_variant() {
        // WR-01 fix: a Panic error must round-trip through the snapshot
        // back to FeedFetchError::Panic, NOT collapse to FeedFetchError::Git.
        let original = FeedFetchError::Panic {
            feed: "OSV".to_string(),
            message: "gix unwound".to_string(),
        };
        let snap = snapshot_err(&original);
        assert!(matches!(snap.kind, FeedFetchErrorKind::Panic));
        assert_eq!(snap.feed, "OSV");
        let recovered = snap.into_error();
        match recovered {
            FeedFetchError::Panic { feed, message } => {
                assert_eq!(feed, "OSV");
                assert_eq!(message, "gix unwound");
            }
            other => panic!("expected Panic, got {other:?}"),
        }
    }

    #[test]
    fn snapshot_err_round_trip_preserves_timeout_variant() {
        let original = FeedFetchError::Timeout {
            feed: "GHSA".to_string(),
            seconds: 120,
        };
        let snap = snapshot_err(&original);
        let recovered = snap.into_error();
        match recovered {
            FeedFetchError::Timeout { feed, seconds } => {
                assert_eq!(feed, "GHSA");
                assert_eq!(seconds, 120);
            }
            other => panic!("expected Timeout, got {other:?}"),
        }
    }

    #[test]
    fn snapshot_err_round_trip_preserves_git_variant() {
        let original = FeedFetchError::Git {
            feed: "OSV".to_string(),
            message: "connect refused".to_string(),
        };
        let snap = snapshot_err(&original);
        let recovered = snap.into_error();
        match recovered {
            FeedFetchError::Git { feed, message } => {
                assert_eq!(feed, "OSV");
                assert_eq!(message, "connect refused");
            }
            other => panic!("expected Git, got {other:?}"),
        }
    }
}
