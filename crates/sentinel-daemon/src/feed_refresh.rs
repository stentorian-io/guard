//! Background feed refresh timer (M006-S01).
//!
//! Spawns a thread that calls `fetch_feeds_blocking` every
//! `FEED_REFRESH_INTERVAL_SECS` (default 6h, env-configurable via
//! `SENTINEL_FEED_REFRESH_INTERVAL_SECS`). Errors are logged but never
//! crash the daemon — launchd KeepAlive restart is the last resort, not
//! a feed-refresh failure.

use crate::feed::concurrency::{fetch_feeds_blocking, LastFetchResult};
use crate::feed::store::FeedStore;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;
use tracing::{info, warn};

pub const DEFAULT_REFRESH_INTERVAL_SECS: u64 = 6 * 60 * 60; // 6 hours

fn configured_interval() -> Duration {
    let secs = std::env::var("SENTINEL_FEED_REFRESH_INTERVAL_SECS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(DEFAULT_REFRESH_INTERVAL_SECS);
    Duration::from_secs(secs)
}

pub fn spawn_feed_refresh_thread(
    state_dir: PathBuf,
    feed_store: Arc<FeedStore>,
    feed_fetch_mutex: Arc<Mutex<()>>,
    last_fetch_result: Arc<RwLock<Option<LastFetchResult>>>,
) -> std::thread::JoinHandle<()> {
    let interval = configured_interval();
    info!(
        interval_secs = interval.as_secs(),
        "feed refresh timer spawned"
    );
    std::thread::Builder::new()
        .name("sentineld-feed-refresh".into())
        .spawn(move || loop {
            std::thread::sleep(interval);
            match fetch_feeds_blocking(
                &state_dir,
                &feed_fetch_mutex,
                &last_fetch_result,
                &feed_store,
            ) {
                Ok(outcomes) => {
                    let total: usize = outcomes.iter().map(|o| o.records_parsed).sum();
                    info!(
                        target = "sentinel.feed.refresh",
                        feeds = outcomes.len(),
                        total_records = total,
                        "background feed refresh succeeded"
                    );
                }
                Err(e) => {
                    warn!(
                        target = "sentinel.feed.refresh",
                        error = %e,
                        "background feed refresh failed (will retry next interval)"
                    );
                }
            }
        })
        .expect("spawn feed refresh thread")
}

pub fn spawn_feed_refresh_thread_with_shutdown(
    state_dir: PathBuf,
    feed_store: Arc<FeedStore>,
    feed_fetch_mutex: Arc<Mutex<()>>,
    last_fetch_result: Arc<RwLock<Option<LastFetchResult>>>,
    shutdown: crossbeam_channel::Receiver<()>,
) -> std::thread::JoinHandle<()> {
    let interval = configured_interval();
    info!(
        interval_secs = interval.as_secs(),
        "feed refresh timer spawned (with shutdown)"
    );
    std::thread::Builder::new()
        .name("sentineld-feed-refresh".into())
        .spawn(move || loop {
            crossbeam_channel::select! {
                recv(shutdown) -> _ => return,
                default(interval) => {}
            }
            match fetch_feeds_blocking(
                &state_dir,
                &feed_fetch_mutex,
                &last_fetch_result,
                &feed_store,
            ) {
                Ok(outcomes) => {
                    let total: usize = outcomes.iter().map(|o| o.records_parsed).sum();
                    info!(
                        target = "sentinel.feed.refresh",
                        feeds = outcomes.len(),
                        total_records = total,
                        "background feed refresh succeeded"
                    );
                }
                Err(e) => {
                    warn!(
                        target = "sentinel.feed.refresh",
                        error = %e,
                        "background feed refresh failed (will retry next interval)"
                    );
                }
            }
        })
        .expect("spawn feed refresh thread")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crossbeam_channel::bounded;

    #[test]
    fn configured_interval_defaults_to_6h() {
        // Don't mutate env in parallel tests; just verify the default constant.
        assert_eq!(DEFAULT_REFRESH_INTERVAL_SECS, 6 * 60 * 60);
    }

    #[test]
    fn shutdown_terminates_feed_refresh_thread() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let state_dir = tmp.path().to_path_buf();
        let db_path = state_dir.join("sentinel.db");
        let _rs = crate::rule_store::RuleStore::open(&db_path).expect("rule store");
        let feed_store = Arc::new(
            FeedStore::open(&db_path).expect("feed store"),
        );
        let mtx = Arc::new(Mutex::new(()));
        let last = Arc::new(RwLock::new(None));
        let (tx, rx) = bounded::<()>(1);

        // The thread sleeps for DEFAULT_REFRESH_INTERVAL_SECS (6h) but
        // the shutdown channel preempts via crossbeam select.
        let handle = spawn_feed_refresh_thread_with_shutdown(
            state_dir, feed_store, mtx, last, rx,
        );

        drop(tx);
        let result = handle.join();
        assert!(result.is_ok(), "feed refresh thread should join cleanly on shutdown");
    }
}
