//! PrepareSnapshot handler.
//!
//! Flow per `sentinel wrap`:
//!   1. CLI sends PrepareSnapshot { cwd } before posix_spawn
//!   2. Concatenates curated allow/deny YAML + SQLite user rules + lockfile-discovered registries
//!   3. Sorts by RuleTier
//!   4. Writes runs/{uuid}.cbor + runs/{uuid}.manifest atomically
//!   5. Inserts RunRecord into ProcessTree (GC will use it on tracked-root exit)
//!   6. Returns SnapshotReply::Ok { manifest_path, run_uuid }

use crate::ipc_server::DaemonState;
use crate::rule_store::RuleStore;
use crate::snapshot::publish_run;
use crate::state_dir::run_manifest_path;
use crate::tracked::{ProcessTree, RunRecord};
use sentinel_core::{AllowlistEntry, MatchType, RuleKind, RuleTier, SCHEMA_V2, Snapshot};
use sentinel_ipc::SnapshotReply;
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

pub fn handle_prepare_snapshot(
    cwd: &Path,
    curated: &[AllowlistEntry],
    rule_store: &RuleStore,
    process_tree: &Arc<ProcessTree>,
    state_dir: &Path,
    is_tty: bool,
    baseline_mode: bool,
) -> SnapshotReply {
    let run_uuid = Uuid::new_v4().to_string();

    let cwd = match validate_cwd(cwd) {
        Ok(p) => p,
        Err(e) => {
            warn!(error = %e, cwd = %cwd.display(), "PrepareSnapshot: rejecting suspicious cwd");
            return SnapshotReply::err(format!("invalid cwd: {e}"));
        }
    };
    let cwd = cwd.as_path();

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

    // 2. Discover lockfile near cwd and extract custom registry hostnames.
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

    // 3. Concatenate + sort by tier.
    let mut entries: Vec<AllowlistEntry> = Vec::with_capacity(
        curated.len() + user_entries.len() + lockfile_entries.len(),
    );
    entries.extend_from_slice(curated);
    entries.extend(user_entries);
    entries.extend(lockfile_entries);
    entries.sort_by_key(|e| e.tier);

    // 4. Build snapshot.
    let snap = Snapshot {
        schema_version: SCHEMA_V2,
        generated_at_unix_ms: unix_ms_now(),
        entries,
        run_uuid: Some(run_uuid.clone()),
    };

    // 5. Publish per-run snapshot.
    let pub_ = match publish_run(state_dir, &snap, &run_uuid) {
        Ok(p) => p,
        Err(e) => {
            return SnapshotReply::err(format!("publish_run: {e}"));
        }
    };

    // 6. Insert RunRecord.
    process_tree.insert_run(RunRecord {
        run_uuid: run_uuid.clone(),
        tracked_root: sentinel_core::AuditToken { val: [0; 8] },
        snapshot_path: pub_.path.clone(),
        manifest_path: run_manifest_path(state_dir, &run_uuid),
        is_tty,
        baseline_mode,
    });

    process_tree.set_run_is_tty(&run_uuid, is_tty);
    process_tree.set_run_baseline_mode(&run_uuid, baseline_mode);

    info!(
        run_uuid = %run_uuid,
        is_tty,
        baseline_mode,
        snapshot = %pub_.path.display(),
        "PrepareSnapshot OK"
    );
    SnapshotReply::ok_v4(
        run_manifest_path(state_dir, &run_uuid).display().to_string(),
        run_uuid,
        Vec::new(),
    )
}

/// Production entry point used by the IPC dispatcher.
pub fn handle_prepare_snapshot_v4_full(
    state: &Arc<DaemonState>,
    cwd: &Path,
    is_tty: bool,
    baseline_mode: bool,
) -> SnapshotReply {
    handle_prepare_snapshot(
        cwd,
        &state.curated,
        &state.rule_store,
        &state.process_tree,
        &state.state_dir,
        is_tty,
        baseline_mode,
    )
}

fn validate_cwd(cwd: &Path) -> Result<std::path::PathBuf, String> {
    let canonical = cwd
        .canonicalize()
        .map_err(|e| format!("canonicalize {}: {e}", cwd.display()))?;
    if !canonical.is_dir() {
        return Err(format!("not a directory: {}", canonical.display()));
    }
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
