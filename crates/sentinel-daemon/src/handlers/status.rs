//! crates/sentinel-daemon/src/handlers/status.rs
//!
//! Phase 3 plan 03-08 — Status IPC handler (CLI-02 / D-69..D-72).
//!
//! Phase 4 plan 04-03 — populates `StatusReply.feeds[]` from `feed_metadata`
//! per D-95 and promotes `daemon_state` to `Degraded` when any feed has
//! `last_pull_outcome != "ok"` (TI-06 surfacing). `StaleFeeds` is reserved
//! for the informational case (any feed `!fresh` but no outright failure)
//! and emitted only when no Degraded condition fires.

use std::sync::atomic::Ordering;

use sentinel_ipc::{
    DaemonStateKind, FeedInfo, GapInfo, InstallInfo, StatusCounters, StatusReply, TrackedRootInfo,
};

use crate::feed::store::{FeedMetadataRow, FeedStore};
use crate::ipc_server::DaemonState;

const ONE_DAY_MS: u64 = 24 * 60 * 60 * 1000;

/// D-95 freshness threshold: a feed is `fresh` iff its last pull was within
/// the last 7 days AND outcome was "ok". Outside the window OR a non-ok
/// outcome → `fresh = false`.
pub const FRESH_THRESHOLD_MS: u64 = 7 * 24 * 60 * 60 * 1000;

/// Production feed names — kept in sync with `feed::fetcher::FEEDS`. The
/// status handler enumerates these so absent metadata rows still produce a
/// FeedInfo entry with `last_pulled_at_ms = None` (rather than silently
/// omitting the feed from the StatusReply).
const FEED_NAMES: &[&str] = &["OSV", "GHSA"];

/// Main IPC handler. Called from ipc_server.rs dispatch arm 0x09 (MessageTag::Status).
pub fn handle_status(state: &DaemonState) -> StatusReply {
    // tracked_roots from process_tree.list_runs()
    let tracked_roots: Vec<TrackedRootInfo> = state
        .process_tree
        .list_runs()
        .into_iter()
        .map(|run| TrackedRootInfo {
            run_uuid: run.run_uuid,
            audit_token: sentinel_ipc::AuditTokenWire::from(run.tracked_root),
            argv: vec![],      // argv not stored on RunRecord in Phase 3; CLI renders as "unknown"
            started_at_ms: 0,  // not stored on RunRecord in Phase 3
        })
        .collect();

    let recent_gaps = state.recent_gaps.snapshot();

    // counters from rule_store + log_writer
    let (blocks, allows, gaps) = state.log_writer.counters_snapshot();
    let counters = StatusCounters {
        rules_user: state.rule_store.count_user_rules().unwrap_or(0),
        blocks_today: blocks,
        allows_today: allows,
        gaps_today: gaps,
    };

    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);

    // Phase 4 plan 04-03 (D-95): populate feeds[] from feed_metadata. The
    // build_feeds_info helper iterates FEED_NAMES so absent rows produce a
    // FeedInfo with last_pulled_at_ms=None / fresh=false rather than being
    // silently dropped.
    let feeds = build_feeds_info(&state.feed_store, now_ms);
    // Phase 4 plan 04-03 (TI-06 surfacing): also pull raw metadata rows so
    // compute_daemon_state can read last_pull_outcome — a row with outcome
    // other than "ok" promotes daemon_state to Degraded.
    let feed_metadata_states = state
        .feed_store
        .read_all_metadata()
        .unwrap_or_else(|e| {
            tracing::warn!(error = %e, "Status: feed_metadata read failed");
            Vec::new()
        });

    // install_info: from install_artifact_store.list_all()
    let install_info = match state.install_artifact_store.list_all() {
        Ok(artifacts) if !artifacts.is_empty() => Some(InstallInfo {
            version: env!("CARGO_PKG_VERSION").to_string(),
            installed_at_ms: artifacts.iter().map(|a| a.installed_at_ms).min().unwrap_or(0),
            artifacts,
        }),
        _ => None,
    };

    // WARNING #6 fix: daemon-computed daemon_state.
    // Phase 4 plan 04-03 (TI-06): also Degraded on any feed_metadata row with
    // last_pull_outcome != "ok"; StaleFeeds emitted only as a softer signal
    // when no Degraded condition fires.
    let snapshot_failed = state
        .last_snapshot_publish_failed
        .load(Ordering::Relaxed);
    let daemon_state =
        compute_daemon_state(&recent_gaps, snapshot_failed, &feeds, &feed_metadata_states, now_ms);

    StatusReply::ok(daemon_state, tracked_roots, recent_gaps, counters, feeds, install_info)
}

/// Pure function for unit testing the Degraded-determination logic.
///
/// Phase 4 plan 04-03 — extended signature: also takes `feeds: &[FeedInfo]`
/// (to read `fresh` for the StaleFeeds path) and `feed_metadata_states:
/// &[FeedMetadataRow]` (to read `last_pull_outcome` for the Degraded path).
///
/// Decision tree (top to bottom; first match wins):
///   1. recent gap within 24h OR snapshot publish failed OR any feed
///      `last_pull_outcome != "ok"` → `Degraded`.
///   2. at least one feed has been pulled before AND any feed is `!fresh`
///      (informational; outcome was ok but stale) → `StaleFeeds`.
///   3. else → `Operational`. (This includes the never-pulled case — a
///      first-run-ever daemon with no `feed_metadata` rows reports
///      Operational rather than StaleFeeds; a stale signal is only
///      meaningful once some feed has been observed at least once.)
pub fn compute_daemon_state(
    recent_gaps: &[GapInfo],
    snapshot_failed: bool,
    feeds: &[FeedInfo],
    feed_metadata_states: &[FeedMetadataRow],
    now_ms: u64,
) -> DaemonStateKind {
    let recent_gap_within_24h = recent_gaps
        .iter()
        .any(|g| now_ms.saturating_sub(g.detected_at_ms) < ONE_DAY_MS);
    let any_feed_failed = feed_metadata_states
        .iter()
        .any(|m| m.last_pull_outcome != "ok");
    if recent_gap_within_24h || snapshot_failed || any_feed_failed {
        return DaemonStateKind::Degraded;
    }
    // StaleFeeds is meaningful only after at least one successful pull has
    // been recorded. A never-pulled daemon (no feed_metadata rows) is NOT
    // stale — it's fresh-install. The Phase 3 e2e tests rely on this:
    // status_state_transitions runs against a fresh daemon harness with
    // SENTINEL_SKIP_FEED_FETCH=1, so no feed_metadata rows exist; the
    // expected state is Operational.
    let has_pull_history = !feed_metadata_states.is_empty();
    let any_feed_stale = feeds.iter().any(|f| !f.fresh);
    if has_pull_history && any_feed_stale {
        return DaemonStateKind::StaleFeeds;
    }
    DaemonStateKind::Operational
}

/// D-95: enumerate FEED_NAMES and produce a FeedInfo per feed. Absent rows
/// are surfaced with `last_pulled_at_ms = None` and `fresh = false` rather
/// than being dropped.
pub fn build_feeds_info(feed_store: &FeedStore, now_ms: u64) -> Vec<FeedInfo> {
    let mut out = Vec::with_capacity(FEED_NAMES.len());
    for feed_name in FEED_NAMES {
        match feed_store.read_metadata(feed_name) {
            Ok(Some(meta)) => {
                let fresh = meta.last_pull_outcome == "ok"
                    && now_ms.saturating_sub(meta.last_pull_ms as u64) < FRESH_THRESHOLD_MS;
                out.push(FeedInfo {
                    name: feed_name.to_string(),
                    last_pulled_at_ms: Some(meta.last_pull_ms as u64),
                    fresh,
                });
            }
            _ => {
                out.push(FeedInfo {
                    name: feed_name.to_string(),
                    last_pulled_at_ms: None,
                    fresh: false,
                });
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn meta(feed: &str, outcome: &str, last_pull_ms: i64) -> FeedMetadataRow {
        FeedMetadataRow {
            feed: feed.to_string(),
            last_pull_ms,
            last_pull_outcome: outcome.to_string(),
            last_commit_sha: None,
            schema_version_observed: None,
            error_message: None,
            record_count: 0,
        }
    }

    #[test]
    fn build_feeds_info_returns_two_entries_with_one_present_one_absent() {
        let store = FeedStore::open_in_memory().unwrap();
        let now_ms = 1_700_000_000_000u64;
        store
            .update_metadata(&meta("OSV", "ok", now_ms as i64))
            .unwrap();
        let feeds = build_feeds_info(&store, now_ms);
        assert_eq!(feeds.len(), 2);
        let osv = feeds.iter().find(|f| f.name == "OSV").unwrap();
        assert_eq!(osv.last_pulled_at_ms, Some(now_ms));
        assert!(osv.fresh, "OSV is fresh — outcome=ok and pulled now");
        let ghsa = feeds.iter().find(|f| f.name == "GHSA").unwrap();
        assert!(ghsa.last_pulled_at_ms.is_none(), "absent → None");
        assert!(!ghsa.fresh, "absent → !fresh");
    }

    #[test]
    fn build_feeds_info_fresh_when_under_7d_and_outcome_ok() {
        let store = FeedStore::open_in_memory().unwrap();
        let now_ms = 1_700_000_000_000u64;
        // 6 days, 23 hours ago → still under 7d threshold.
        let recent = (now_ms - (6 * 24 + 23) * 60 * 60 * 1000) as i64;
        store.update_metadata(&meta("OSV", "ok", recent)).unwrap();
        let feeds = build_feeds_info(&store, now_ms);
        let osv = feeds.iter().find(|f| f.name == "OSV").unwrap();
        assert!(osv.fresh);
    }

    #[test]
    fn build_feeds_info_not_fresh_when_outside_7d_window_even_if_ok() {
        let store = FeedStore::open_in_memory().unwrap();
        let now_ms = 1_700_000_000_000u64;
        // 8 days ago — outside threshold.
        let stale = (now_ms - 8 * 24 * 60 * 60 * 1000) as i64;
        store.update_metadata(&meta("OSV", "ok", stale)).unwrap();
        let feeds = build_feeds_info(&store, now_ms);
        let osv = feeds.iter().find(|f| f.name == "OSV").unwrap();
        assert!(!osv.fresh);
    }

    #[test]
    fn build_feeds_info_not_fresh_when_outcome_not_ok_even_if_recent() {
        let store = FeedStore::open_in_memory().unwrap();
        let now_ms = 1_700_000_000_000u64;
        store
            .update_metadata(&meta("OSV", "parse_error", now_ms as i64))
            .unwrap();
        let feeds = build_feeds_info(&store, now_ms);
        let osv = feeds.iter().find(|f| f.name == "OSV").unwrap();
        assert!(!osv.fresh, "outcome=parse_error → fresh=false");
    }

    #[test]
    fn compute_daemon_state_degraded_on_feed_outcome_not_ok() {
        let now = 1_700_000_000_000u64;
        let metas = vec![meta("OSV", "parse_error", now as i64)];
        let feeds = vec![FeedInfo {
            name: "OSV".to_string(),
            last_pulled_at_ms: Some(now),
            fresh: false,
        }];
        assert!(matches!(
            compute_daemon_state(&[], false, &feeds, &metas, now),
            DaemonStateKind::Degraded
        ));
    }

    #[test]
    fn compute_daemon_state_stale_feeds_when_outcome_ok_but_old() {
        let now = 1_700_000_000_000u64;
        let stale_ms = (now - 8 * 24 * 60 * 60 * 1000) as i64;
        let metas = vec![meta("OSV", "ok", stale_ms)];
        let feeds = vec![FeedInfo {
            name: "OSV".to_string(),
            last_pulled_at_ms: Some(stale_ms as u64),
            fresh: false,
        }];
        assert!(matches!(
            compute_daemon_state(&[], false, &feeds, &metas, now),
            DaemonStateKind::StaleFeeds
        ));
    }

    #[test]
    fn compute_daemon_state_operational_when_never_pulled_yet() {
        // First-run-ever daemon: no feed_metadata rows. The build_feeds_info
        // call returns 2 FeedInfo entries with `fresh=false` (because
        // last_pulled_at_ms=None), but compute_daemon_state should NOT
        // promote to StaleFeeds — staleness only fires after at least one
        // pull has been recorded.
        let now = 1_700_000_000_000u64;
        let feeds = vec![
            FeedInfo {
                name: "OSV".to_string(),
                last_pulled_at_ms: None,
                fresh: false,
            },
            FeedInfo {
                name: "GHSA".to_string(),
                last_pulled_at_ms: None,
                fresh: false,
            },
        ];
        // No feed_metadata rows.
        assert!(matches!(
            compute_daemon_state(&[], false, &feeds, &[], now),
            DaemonStateKind::Operational
        ));
    }

    #[test]
    fn compute_daemon_state_operational_when_all_feeds_fresh() {
        let now = 1_700_000_000_000u64;
        let metas = vec![meta("OSV", "ok", now as i64), meta("GHSA", "ok", now as i64)];
        let feeds = vec![
            FeedInfo {
                name: "OSV".to_string(),
                last_pulled_at_ms: Some(now),
                fresh: true,
            },
            FeedInfo {
                name: "GHSA".to_string(),
                last_pulled_at_ms: Some(now),
                fresh: true,
            },
        ];
        assert!(matches!(
            compute_daemon_state(&[], false, &feeds, &metas, now),
            DaemonStateKind::Operational
        ));
    }
}
