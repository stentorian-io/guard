//! PrepareSnapshot handler.
//!
//! Legacy flow still supports daemon-built snapshots for compatibility. The
//! signed-snapshot flow splits this into collecting verified inputs, letting the
//! CLI build and hardware-sign exact snapshot bytes, and then publishing those
//! bytes verbatim.

use crate::ipc_server::{DaemonState, PendingSnapshotInput};
use crate::rule_store::RuleStore;
use crate::snapshot::{publish_run, publish_run_signed_bytes};
use crate::state_dir::run_manifest_path;
use crate::tracked::{ProcessTree, RunRecord};
use guard_core::{AllowlistEntry, MatchType, RuleKind, RuleTier, SnapshotBuildInput};
use guard_ipc::{PublishSignedSnapshot, SnapshotInputsReply, SnapshotReply};
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tracing::{debug, info, warn};

const PENDING_SNAPSHOT_INPUT_TTL: Duration = Duration::from_secs(10 * 60);

#[derive(Debug, thiserror::Error)]
pub enum PrepareError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("rule_store: {0}")]
    RuleStore(String),
    #[error("merge: {0}")]
    Merge(String),
}

pub struct CollectedSnapshotBuildInput {
    pub input: SnapshotBuildInput,
    pub is_tty: bool,
    pub baseline_mode: bool,
}

fn new_run_uuid() -> Result<String, String> {
    let mut buf = [0u8; 16];
    getrandom::getrandom(&mut buf).map_err(|_| "getrandom failed".to_string())?;
    buf[6] = (buf[6] & 0x0f) | 0x40; // version 4
    buf[8] = (buf[8] & 0x3f) | 0x80; // variant 1
    Ok(format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        buf[0],
        buf[1],
        buf[2],
        buf[3],
        buf[4],
        buf[5],
        buf[6],
        buf[7],
        buf[8],
        buf[9],
        buf[10],
        buf[11],
        buf[12],
        buf[13],
        buf[14],
        buf[15],
    ))
}

fn collect_snapshot_build_input(
    cwd: &Path,
    curated: &[AllowlistEntry],
    rule_store: &RuleStore,
    rule_signature_policy: guard_core::RuleSignaturePolicy,
    is_tty: bool,
    baseline_mode: bool,
) -> Result<CollectedSnapshotBuildInput, String> {
    let run_uuid = new_run_uuid()?;
    let cwd = validate_cwd(cwd).map_err(|e| {
        warn!(error = %e, cwd = %cwd.display(), "PrepareSnapshot: rejecting suspicious cwd");
        format!("invalid cwd: {e}")
    })?;
    let cwd = cwd.as_path();

    let disabled = match rule_store.disabled_curated_patterns() {
        Ok(d) => d,
        Err(e) => {
            warn!(
                error = %e,
                "PrepareSnapshot: disabled_curated_patterns read failed; proceeding with all curated rules"
            );
            std::collections::HashSet::new()
        }
    };
    if !disabled.is_empty() {
        info!(
            disabled_count = disabled.len(),
            "PrepareSnapshot: filtering disabled curated rules"
        );
    }

    let verified_user_entries = rule_store
        .all_verified_user_rules(rule_signature_policy)
        .map_err(|e| {
            warn!(
                error = %e,
                "PrepareSnapshot: user rule signature verification failed; failing closed"
            );
            format!("user rule signature verification failed: {e}")
        })?;

    let lockfile_entries: Vec<AllowlistEntry> = match guard_core::lockfile::discover_lockfile(cwd) {
        Some(lockfile_path) => match guard_core::lockfile::extract_registries(&lockfile_path) {
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
                            lr.lockfile_path
                                .file_name()
                                .unwrap_or_default()
                                .to_string_lossy()
                        ),
                    })
                    .collect()
            }
            None => Vec::new(),
        },
        None => Vec::new(),
    };

    Ok(CollectedSnapshotBuildInput {
        input: SnapshotBuildInput {
            run_uuid,
            generated_at_unix_ms: unix_ms_now(),
            curated_entries: curated.to_vec(),
            disabled_curated_patterns: disabled.iter().cloned().collect(),
            verified_user_entries,
            lockfile_entries,
        },
        is_tty,
        baseline_mode,
    })
}

fn record_run(
    process_tree: &Arc<ProcessTree>,
    state_dir: &Path,
    run_uuid: &str,
    snapshot_path: std::path::PathBuf,
    is_tty: bool,
    baseline_mode: bool,
) {
    process_tree.insert_run(RunRecord {
        run_uuid: run_uuid.to_string(),
        tracked_root: guard_core::AuditToken { val: [0; 8] },
        snapshot_path,
        manifest_path: run_manifest_path(state_dir, run_uuid),
        is_tty,
        baseline_mode,
    });
    process_tree.set_run_is_tty(run_uuid, is_tty);
    process_tree.set_run_baseline_mode(run_uuid, baseline_mode);
}

#[allow(clippy::too_many_arguments)]
pub fn handle_prepare_snapshot(
    cwd: &Path,
    curated: &[AllowlistEntry],
    rule_store: &RuleStore,
    process_tree: &Arc<ProcessTree>,
    state_dir: &Path,
    rule_signature_policy: guard_core::RuleSignaturePolicy,
    is_tty: bool,
    baseline_mode: bool,
) -> SnapshotReply {
    let collected = match collect_snapshot_build_input(
        cwd,
        curated,
        rule_store,
        rule_signature_policy,
        is_tty,
        baseline_mode,
    ) {
        Ok(collected) => collected,
        Err(e) => return SnapshotReply::err(e),
    };
    let run_uuid = collected.input.run_uuid.clone();
    let snap = guard_core::build_snapshot(collected.input);

    let pub_ = match publish_run(state_dir, &snap, &run_uuid) {
        Ok(p) => p,
        Err(e) => return SnapshotReply::err(format!("publish_run: {e}")),
    };

    record_run(
        process_tree,
        state_dir,
        &run_uuid,
        pub_.path.clone(),
        is_tty,
        baseline_mode,
    );

    info!(
        run_uuid = %run_uuid,
        is_tty,
        baseline_mode,
        snapshot = %pub_.path.display(),
        "PrepareSnapshot OK"
    );
    SnapshotReply::ok(
        run_manifest_path(state_dir, &run_uuid)
            .display()
            .to_string(),
        run_uuid,
    )
}

fn prune_pending_snapshot_inputs(state: &Arc<DaemonState>) {
    state
        .pending_snapshot_inputs
        .lock()
        .expect("pending snapshot inputs mutex")
        .retain(|_, pending| pending.prepared_at.elapsed() < PENDING_SNAPSHOT_INPUT_TTL);
}

pub fn handle_prepare_snapshot_inputs_full(
    state: &Arc<DaemonState>,
    cwd: &Path,
    is_tty: bool,
    baseline_mode: bool,
) -> SnapshotInputsReply {
    prune_pending_snapshot_inputs(state);
    match collect_snapshot_build_input(
        cwd,
        &state.curated,
        &state.rule_store,
        state.rule_signature_policy,
        is_tty,
        baseline_mode,
    ) {
        Ok(collected) => {
            state
                .pending_snapshot_inputs
                .lock()
                .expect("pending snapshot inputs mutex")
                .insert(
                    collected.input.run_uuid.clone(),
                    PendingSnapshotInput {
                        input: collected.input.clone(),
                        is_tty: collected.is_tty,
                        baseline_mode: collected.baseline_mode,
                        prepared_at: Instant::now(),
                    },
                );
            SnapshotInputsReply::ok(collected.input, collected.is_tty, collected.baseline_mode)
        }
        Err(e) => SnapshotInputsReply::err(e),
    }
}

pub fn handle_publish_signed_snapshot_full(
    state: &Arc<DaemonState>,
    req: PublishSignedSnapshot,
) -> SnapshotReply {
    if req.schema_version != guard_ipc::IPC_SCHEMA_V5 {
        return SnapshotReply::err(format!(
            "schema_version {} != IPC_SCHEMA_V5",
            req.schema_version
        ));
    }
    prune_pending_snapshot_inputs(state);
    let Some(pending) = state
        .pending_snapshot_inputs
        .lock()
        .expect("pending snapshot inputs mutex")
        .remove(&req.run_uuid)
    else {
        return SnapshotReply::err("signed snapshot was not prepared by daemon");
    };
    if pending.is_tty != req.is_tty || pending.baseline_mode != req.baseline_mode {
        return SnapshotReply::err("signed snapshot run flags mismatch");
    }
    let expected_bytes = match guard_core::build_snapshot_bytes(pending.input) {
        Ok(bytes) => bytes,
        Err(e) => return SnapshotReply::err(format!("rebuild prepared snapshot: {e}")),
    };
    if expected_bytes != req.snapshot_bytes {
        return SnapshotReply::err("signed snapshot bytes do not match daemon-issued inputs");
    }
    let snapshot = match guard_core::Snapshot::decode(&req.snapshot_bytes) {
        Ok(snapshot) => snapshot,
        Err(e) => return SnapshotReply::err(format!("decode signed snapshot: {e}")),
    };
    if snapshot.run_uuid.as_deref() != Some(req.run_uuid.as_str()) {
        return SnapshotReply::err("signed snapshot run_uuid mismatch");
    }
    let digest_hex = guard_core::sha256_hex(&req.snapshot_bytes);
    let payload = guard_core::SnapshotSignaturePayloadV1::new(
        req.run_uuid.clone(),
        digest_hex,
        snapshot.generated_at_unix_ms,
    );
    if let Err(e) =
        guard_core::verify_snapshot_signature(&payload, &req.signature, state.rule_signature_policy)
    {
        return SnapshotReply::err(format!("snapshot signature verification failed: {e}"));
    }
    match state
        .rule_store
        .is_trusted_rule_signer(&req.signature.public_key_sha256, &req.signature.signer_kind)
    {
        Ok(true) => {}
        Ok(false) => {
            return SnapshotReply::err(format!(
                "snapshot signer is not trusted: kind={} fingerprint={}",
                req.signature.signer_kind, req.signature.public_key_sha256
            ));
        }
        Err(e) => return SnapshotReply::err(format!("snapshot signer trust check failed: {e}")),
    }
    match publish_run_signed_bytes(
        &state.state_dir,
        &req.snapshot_bytes,
        &req.run_uuid,
        &req.signature,
    ) {
        Ok(pub_) => {
            record_run(
                &state.process_tree,
                &state.state_dir,
                &req.run_uuid,
                pub_.path.clone(),
                req.is_tty,
                req.baseline_mode,
            );
            info!(
                run_uuid = %req.run_uuid,
                is_tty = req.is_tty,
                baseline_mode = req.baseline_mode,
                snapshot = %pub_.path.display(),
                "PublishSignedSnapshot OK"
            );
            SnapshotReply::ok(
                run_manifest_path(&state.state_dir, &req.run_uuid)
                    .display()
                    .to_string(),
                req.run_uuid,
            )
        }
        Err(e) => SnapshotReply::err(format!("publish signed snapshot: {e}")),
    }
}

/// Production entry point used by the IPC dispatcher.
pub fn handle_prepare_snapshot_v4_full(
    _state: &Arc<DaemonState>,
    _cwd: &Path,
    _is_tty: bool,
    _baseline_mode: bool,
) -> SnapshotReply {
    SnapshotReply::err(
        "signed snapshot flow required; use PrepareSnapshotInputs and PublishSignedSnapshot",
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
        if canonical_str == *prefix || canonical_str.starts_with(&format!("{prefix}/")) {
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
