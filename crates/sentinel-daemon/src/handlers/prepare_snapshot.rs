//! PrepareSnapshot handler.
//!
//! Flow per `sentinel wrap`:
//!   1. CLI sends PrepareSnapshot { cwd } before posix_spawn
//!   2. Concatenates curated YAML + SQLite user rules + lockfile-discovered registries
//!   3. Merges FeedDeny entries from threat-intel IOCs
//!   4. Sorts by RuleTier
//!   5. Writes runs/{uuid}.cbor + runs/{uuid}.manifest atomically
//!   6. Inserts RunRecord into ProcessTree (GC will use it on tracked-root exit)
//!   7. Returns SnapshotReply::Ok { manifest_path, run_uuid }
//!
//! v0.3 (IPC_SCHEMA_V3): handler now accepts V3 payloads carrying
//! `is_tty` and `baseline_mode`. The dispatcher in ipc_server.rs
//! relaxes the schema check to `matches!(v, IPC_SCHEMA_V2 | IPC_SCHEMA_V3)` and
//! passes those fields through as arguments. V2 callers receive false/false defaults
//! via #[serde(default)] on the wire fields.

use crate::ipc_server::DaemonState;
use crate::rule_store::RuleStore;
use crate::snapshot::publish_run;
use crate::state_dir::run_manifest_path;
use crate::tracked::{ProcessTree, RunRecord};
use sentinel_core::{AllowlistEntry, MatchType, RuleKind, RuleTier, SCHEMA_V2, Snapshot};
use sentinel_ipc::{FeedWarning, SnapshotReply};
use std::path::Path;
use std::sync::Arc;
use tracing::{debug, info, warn};
use uuid::Uuid;

#[derive(Debug, thiserror::Error)]
pub enum PrepareError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("rule_store: {0}")]
    RuleStore(String),
    #[error("merge: {0}")]
    Merge(String),
}

/// Inputs are passed by reference; outputs are the SnapshotReply to write back.
///
/// v0.3: `is_tty` and `baseline_mode` are V3 fields; they default
/// to false on V2 callers. Propagated via `set_run_is_tty` / `set_run_baseline_mode`
/// after RunRecord insertion.
///
/// v0.4: the production handler is
/// [`handle_prepare_snapshot_v4_full`], which performs:
///   1. `fetch_feeds_blocking(...)` BEFORE building the snapshot (pure
///      on-demand). Strict-fail on fetch error -> SnapshotReply::Err.
///   2. User / curated / lockfile entries assembly (existing v0.2 path).
///   3. `build_feeddeny_entries(feed_store)` merge step.
///   4. Sort + publish per-run snapshot.
///   5. SnapshotReply::ok_v4 carrying any non-fatal `feed_warnings`.
///
/// This pre-v0.4 entry point delegates to `handle_prepare_snapshot_inner`
/// with `feed_store = None` (so the fetch-and-merge step is skipped) and is
/// kept as a thin shim so existing tests that pass individual subsystems
/// (rather than a full DaemonState) still compile.
pub fn handle_prepare_snapshot(
    cwd: &Path,
    curated: &[AllowlistEntry],
    rule_store: &RuleStore,
    process_tree: &Arc<ProcessTree>,
    state_dir: &Path,
    is_tty: bool,
    baseline_mode: bool,
) -> SnapshotReply {
    handle_prepare_snapshot_inner(
        cwd,
        curated,
        rule_store,
        process_tree,
        state_dir,
        is_tty,
        baseline_mode,
        /* feed_store */ None,
        /* feed_fetch_mutex */ None,
        /* last_fetch_result */ None,
    )
}

// WR-10 fix: removed `handle_prepare_snapshot_v4(state, cwd)` —
// it always defaulted `is_tty` + `baseline_mode` to false and was
// never reached at runtime (the IPC dispatcher in
// `ipc_server.rs::handle_prepare_snapshot_frame` calls
// `handle_prepare_snapshot_v4_full` with the on-wire V3 fields).
// Keeping a dead-code shim was a maintenance trap: a future refactor
// could accidentally route to the shim and silently drop the V3 TTY
// signal (suppressing baseline-mode dispatch / interactive prompts).
//
// Production V4 entry point follows.

/// Full v0.4 entry point used by the V3 IPC dispatcher path: takes the
/// V3-specific `is_tty` + `baseline_mode` fields plus the DaemonState for feed
/// access. This is what `ipc_server.rs::handle_prepare_snapshot_frame` calls.
///
/// This is the ONLY production entry point that wires feed primitives
/// from `DaemonState`. The legacy `handle_prepare_snapshot` (above) is
/// retained for unit tests that build subsystems by hand.
pub fn handle_prepare_snapshot_v4_full(
    state: &Arc<DaemonState>,
    cwd: &Path,
    is_tty: bool,
    baseline_mode: bool,
) -> SnapshotReply {
    handle_prepare_snapshot_inner(
        cwd,
        &state.curated,
        &state.rule_store,
        &state.process_tree,
        &state.state_dir,
        is_tty,
        baseline_mode,
        Some(&state.feed_store),
        Some(&state.feed_fetch_mutex),
        Some(&state.last_fetch_result),
    )
}

/// Test seam: same shape as the private `handle_prepare_snapshot_inner` but
/// public so integration tests in `tests/prepare_snapshot_tests.rs` can
/// exercise the V4 path with custom `curated` slices (the V4 entry points
/// always read `state.curated`, which is empty in the test DaemonState).
#[allow(clippy::too_many_arguments)]
pub fn handle_prepare_snapshot_inner_for_tests(
    cwd: &Path,
    curated: &[AllowlistEntry],
    rule_store: &RuleStore,
    process_tree: &Arc<ProcessTree>,
    state_dir: &Path,
    is_tty: bool,
    baseline_mode: bool,
    feed_store: Option<&Arc<crate::feed::store::FeedStore>>,
    feed_fetch_mutex: Option<&Arc<std::sync::Mutex<()>>>,
    last_fetch_result: Option<
        &Arc<std::sync::RwLock<Option<crate::feed::concurrency::LastFetchResult>>>,
    >,
) -> SnapshotReply {
    handle_prepare_snapshot_inner(
        cwd,
        curated,
        rule_store,
        process_tree,
        state_dir,
        is_tty,
        baseline_mode,
        feed_store,
        feed_fetch_mutex,
        last_fetch_result,
    )
}

#[allow(clippy::too_many_arguments)]
fn handle_prepare_snapshot_inner(
    cwd: &Path,
    curated: &[AllowlistEntry],
    rule_store: &RuleStore,
    process_tree: &Arc<ProcessTree>,
    state_dir: &Path,
    is_tty: bool,
    baseline_mode: bool,
    feed_store: Option<&Arc<crate::feed::store::FeedStore>>,
    feed_fetch_mutex: Option<&Arc<std::sync::Mutex<()>>>,
    last_fetch_result: Option<
        &Arc<std::sync::RwLock<Option<crate::feed::concurrency::LastFetchResult>>>,
    >,
) -> SnapshotReply {
    let run_uuid = Uuid::new_v4().to_string();

    // CR-05: validate the wire-claimed cwd before walking the filesystem from
    // it. A same-uid local attacker could send `cwd = "/Users/victim/.ssh"`
    // and trigger lockfile discovery from a suspicious location. Although the
    // v1 trust boundary is same-uid only, refusing obviously-suspicious paths
    // is cheap defense-in-depth.
    let cwd = match validate_cwd(cwd) {
        Ok(p) => p,
        Err(e) => {
            warn!(error = %e, cwd = %cwd.display(), "PrepareSnapshot: rejecting suspicious cwd");
            return SnapshotReply::err(format!("invalid cwd: {e}"));
        }
    };
    let cwd = cwd.as_path();

    // v0.4 step 0: pre-flight feed fetch BEFORE building
    // the snapshot. Strict-fail on error — no last-cached fallback at
    // the run gate. Skip when no feed_store is wired (legacy callers + unit
    // tests that don't exercise the feed path).
    let feed_warnings: Vec<FeedWarning> =
        match (feed_store, feed_fetch_mutex, last_fetch_result) {
            (Some(fs), Some(mtx), Some(last)) => {
                match crate::feed::concurrency::fetch_feeds_blocking(state_dir, mtx, last, fs) {
                    Ok(outcomes) => {
                        outcomes.iter().flat_map(|o| o.warnings.iter().cloned()).collect()
                    }
                    Err(e) => {
                        warn!(error = %e, "PrepareSnapshot: feed fetch failed");
                        return SnapshotReply::err(format!("feed fetch: {e}"));
                    }
                }
            }
            _ => Vec::new(),
        };

    // 1. SQLite user rules.
    let user_entries = match rule_store.all_user_rules() {
        Ok(r) => r,
        Err(e) => {
            warn!(
                error = %e,
                "PrepareSnapshot: rule_store read failed; proceeding without user rules"
            );
            Vec::new()
        }
    };

    // 1a. v0.4: merge FeedDeny entries derived from
    //     feed_iocs WHERE host_ioc IS NOT NULL. Non-fatal failure path follows
    //     the existing project-entries / user-entries discipline (warn + empty
    //     vec). The structural invariant — `RuleTier::CuratedAllow=1 <
    //     RuleTier::FeedDeny=4` — is enforced by the sort step below; this
    //     handler does NOT need to special-case curated overrides.
    let feeddeny_entries: Vec<AllowlistEntry> = match feed_store {
        Some(fs) => match crate::feed::build_feeddeny_entries(fs) {
            Ok(e) => e,
            Err(err) => {
                warn!(
                    error = %err,
                    "PrepareSnapshot: feed_iocs read failed; proceeding without FeedDeny"
                );
                Vec::new()
            }
        },
        None => Vec::new(),
    };

    // 1b. M003-S07: discover lockfile near cwd and extract custom registry
    //     hostnames. These become CuratedAllow entries so private-registry
    //     fetches are not blocked. Non-fatal: log and continue if anything fails.
    let lockfile_entries: Vec<AllowlistEntry> =
        match sentinel_core::lockfile::discover_lockfile(cwd) {
            Some(lockfile_path) => {
                match sentinel_core::lockfile::extract_registries(&lockfile_path) {
                    Some(lr) => {
                        debug!(
                            lockfile = %lr.lockfile_path.display(),
                            count = lr.registries.len(),
                            "lockfile registries discovered"
                        );
                        lr.registries
                            .into_iter()
                            .map(|host| AllowlistEntry {
                                kind: RuleKind::Allow,
                                tier: RuleTier::CuratedAllow,
                                match_type: MatchType::Exact,
                                pattern: host,
                                reason: format!(
                                    "lockfile: {}",
                                    lr.lockfile_path.file_name().unwrap_or_default().to_string_lossy()
                                ),
                            })
                            .collect()
                    }
                    None => Vec::new(),
                }
            }
            None => Vec::new(),
        };

    // 2. Concatenate + sort by tier.
    let mut entries: Vec<AllowlistEntry> = Vec::with_capacity(
        curated.len()
            + user_entries.len()
            + feeddeny_entries.len()
            + lockfile_entries.len(),
    );
    entries.extend_from_slice(curated);
    entries.extend(user_entries);
    entries.extend(feeddeny_entries);
    entries.extend(lockfile_entries);
    entries.sort_by_key(|e| e.tier);

    // 3. Build snapshot.
    let snap = Snapshot {
        schema_version: SCHEMA_V2,
        generated_at_unix_ms: unix_ms_now(),
        entries,
        run_uuid: Some(run_uuid.clone()),
    };

    // 4. Publish per-run snapshot.
    let pub_ = match publish_run(state_dir, &snap, &run_uuid) {
        Ok(p) => p,
        Err(e) => {
            return SnapshotReply::err(format!("publish_run: {e}"));
        }
    };

    // 5. Insert RunRecord. The tracked_root is unknown at this point (the
    //    CLI hasn't sent RegisterRoot yet). We record the run with a zero
    //    audit_token; the RegisterRoot handler updates it later.
    //
    //    v0.3: is_tty and baseline_mode are set at insertion.
    process_tree.insert_run(RunRecord {
        run_uuid: run_uuid.clone(),
        tracked_root: sentinel_core::AuditToken { val: [0; 8] },
        snapshot_path: pub_.path.clone(),
        manifest_path: run_manifest_path(state_dir, &run_uuid),
        is_tty,
        baseline_mode,
    });

    // v0.3: also apply via setters so any downstream code that
    // calls set_run_is_tty / set_run_baseline_mode (e.g. from a V3 ipc_server
    // frame that decodes AFTER insert_run) will see up-to-date values. For the
    // standard V2/V3 path the values are already correct from insert_run above;
    // these setters are a no-op in that case but document the IPC_SCHEMA_V3 intent.
    process_tree.set_run_is_tty(&run_uuid, is_tty);
    process_tree.set_run_baseline_mode(&run_uuid, baseline_mode);

    info!(
        run_uuid = %run_uuid,
        is_tty,
        baseline_mode,
        snapshot = %pub_.path.display(),
        feed_warnings_n = feed_warnings.len(),
        "PrepareSnapshot OK"
    );
    SnapshotReply::ok_v4(
        run_manifest_path(state_dir, &run_uuid).display().to_string(),
        run_uuid,
        feed_warnings,
    )
}

/// CR-05: canonicalize the wire-claimed cwd and reject obviously-suspicious
/// system paths. The path must (a) exist, (b) be a directory, (c) canonicalize
/// successfully, and (d) not be inside a list of system directories the daemon
/// should never walk.
fn validate_cwd(cwd: &Path) -> Result<std::path::PathBuf, String> {
    let canonical = cwd
        .canonicalize()
        .map_err(|e| format!("canonicalize {}: {e}", cwd.display()))?;
    if !canonical.is_dir() {
        return Err(format!("not a directory: {}", canonical.display()));
    }
    // System path denylist — defense-in-depth, not the trust boundary itself.
    const FORBIDDEN_PREFIXES: &[&str] = &[
        "/etc",
        "/private/etc",
        "/System",
        "/usr/bin",
        "/usr/sbin",
        "/sbin",
        "/bin",
        "/var/db",
        "/var/root",
    ];
    let canonical_str = canonical.to_string_lossy();
    for prefix in FORBIDDEN_PREFIXES {
        if canonical_str == *prefix
            || canonical_str.starts_with(&format!("{prefix}/"))
        {
            return Err(format!(
                "cwd in forbidden system path: {}",
                canonical.display()
            ));
        }
    }
    Ok(canonical)
}

fn unix_ms_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64
}
