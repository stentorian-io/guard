//! Sync `UnixListener` accept loop with bounded thread pool dispatch.
//!
//! v0.2: synchronous fork/exec IPC volume requires real concurrency.
//! 16 worker threads consume from a bounded channel; accept never blocks on
//! a worker. Under sustained flood the channel fills, accept's `try_send`
//! returns Err, the new connection is dropped, the dylib's IPC times out
//! at 250ms, and the dylib fails-closed at fork — the safe outcome.
//!
//! Backward compat: v0.1 `RegisterRoot` frames (length-prefixed CBOR) are
//! detected by `classify_frame` and dispatched to the legacy register handler.
//! The v0.1 contract is preserved (FROZEN status).
//!
//! BENIGN-EOF CONTRACT: `probe_daemon_alive` is a
//! connect-only liveness probe — it opens a stream and drops it immediately,
//! sending no frame. From this side, `classify_frame` returns
//! `DispatchError::Io(e)` where `e.kind() == ErrorKind::UnexpectedEof`. We
//! recognize that case as a benign liveness probe: log at debug, mutate no
//! state, write no Reply, close.

use crate::baseline_staging::BaselineStaging;
use crate::gap_detector::GapDetector;
use crate::install_artifacts::InstallArtifactStore;
use crate::ipc_dispatch::{DispatchError, FrameKind, MessageTag, classify_frame};
use crate::log_writer::LogWriter;
use crate::peer_auth::authenticate;
use crate::prompt::{PromptDedup, RecentGapsRing};
use crate::tracked::{CoverageGap, ProcessTree};
use crossbeam_channel::{TrySendError, bounded};
use guard_core::AuditToken;
use guard_ipc::frame::write_frame;
use guard_ipc::{
    BaselineCommit, BaselineCommitReply, DeleteInstallArtifacts, DeleteInstallArtifactsReply,
    DenyNotify, DenyNotifyAck, DisableCuratedRule, DisableCuratedRuleReply, DylibLoaded,
    DylibLoadedAck, EnableCuratedRule, EnableCuratedRuleReply, EnvNotPropagatedGap,
    EnvNotPropagatedGapAck, ExecAck, ExecBlocked, ExecBlockedAck, ExecEvent, ForkAck, ForkEvent,
    IPC_SCHEMA_V2, IPC_SCHEMA_V3, IPC_SCHEMA_V4, IPC_SCHEMA_V5, InsertUserRule,
    InsertUserRuleReply, IpcError, ListRules, ListRulesReply, PersistenceWrite,
    PersistenceWriteAck, Ping, PingReply, PrepareSnapshot, PromptChannelInit, PromptChannelInitAck,
    PublishSignedSnapshot, ReadInstallArtifacts, ReadInstallArtifactsReply, RegisterRoot, Reply,
    Resolve, ResolveReply, SnapshotInputsReply, SnapshotReply, Status, StatusReply,
};
use guard_os::codesign::is_hardened_runtime;
use guard_os::process::{kernel_pidversion, process_uid};
use std::collections::HashMap;
use std::io::{ErrorKind, Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};
use tracing::{debug, error, info, warn};

// ============================================================================
// v0.3 — DeferredResolveTable
// ============================================================================

/// An entry parked in the `DeferredResolveTable` waiting for a user prompt response.
pub struct DeferredEntry {
    pub run_uuid: String,
    pub host: String,
    pub port: u16,
    pub sender: crossbeam_channel::Sender<guard_core::Verdict>,
    /// v0.5: package context resolved at prompt-build time, replayed
    /// when `emit_decision_row` fires from the response handler. None if the peer
    /// process tree has no PM ancestor (no npm_/CARGO_/PIP_ env signal).
    pub package_context: Option<guard_ipc::PackageContext>,
}

/// Maps `prompt_id` → `DeferredEntry`. The Resolve handler inserts when parking;
/// the prompt-channel handler takes when `PromptResponse` arrives.
pub struct DeferredResolveTable {
    pending: Mutex<HashMap<String, DeferredEntry>>,
    counter: AtomicU64,
}

impl DeferredResolveTable {
    #[must_use]
    pub fn new() -> Self {
        Self {
            pending: Mutex::new(HashMap::new()),
            counter: AtomicU64::new(0),
        }
    }

    /// Generate a fresh, unique `prompt_id` string ("p-00000042" style).
    pub fn next_prompt_id(&self) -> String {
        let n = self.counter.fetch_add(1, Ordering::Relaxed);
        format!("p-{n:08}")
    }

    pub fn insert(&self, prompt_id: String, entry: DeferredEntry) {
        let mut g = self
            .pending
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        g.insert(prompt_id, entry);
    }

    /// Remove the entry and return its Sender. Returns None if already taken.
    pub fn take(&self, prompt_id: &str) -> Option<crossbeam_channel::Sender<guard_core::Verdict>> {
        let mut g = self
            .pending
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        g.remove(prompt_id).map(|e| e.sender)
    }

    /// WR-11: `take_full` removes the entry and returns the entire `DeferredEntry`,
    /// so callers can use the (`run_uuid`, host, port) tuple to also clear the
    /// `PromptDedup` map for the same connection. `dispatch_response` / `dispatch_cancel`
    /// use this so dedup entries don't pile up over a long run's lifetime.
    pub fn take_full(&self, prompt_id: &str) -> Option<DeferredEntry> {
        let mut g = self
            .pending
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        g.remove(prompt_id)
    }

    /// CR-02: per-run `prompt_id` ownership. Returns the entry only when its
    /// `run_uuid` matches `run_uuid`. On mismatch the entry stays in the
    /// table (so its rightful owner can still resolve it). Atomic w.r.t.
    /// concurrent take/insert because the peek and remove run under the
    /// same mutex guard — eliminates the take-then-reinsert race.
    ///
    /// Returns:
    /// - Some(entry) when the entry exists and `run_uuid` matches.
    /// - None when the entry is absent OR the `run_uuid` does not match.
    ///   Callers cannot distinguish absent-vs-foreign through the return
    ///   alone; the boolean fork is exposed via `take_full_if_owned` for
    ///   handlers that need to log the cross-run case.
    pub fn take_full_for_run(&self, prompt_id: &str, run_uuid: &str) -> Option<DeferredEntry> {
        let mut g = self
            .pending
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        match g.get(prompt_id) {
            Some(e) if e.run_uuid != run_uuid => None,
            _ => g.remove(prompt_id),
        }
    }

    /// CR-02 helper for handlers that need to distinguish "not present" from
    /// "present but owned by another run". Returns:
    /// - `Ok(Some(entry))` — entry was present AND `run_uuid` matched; entry consumed.
    /// - `Ok(None)`        — entry was absent (already taken or never inserted).
    /// - `Err(foreign_run_uuid)` — entry was present but owned by a different
    ///   run; entry left in place. Caller should log a structured warning and
    ///   ignore the wire-side response.
    ///
    /// # Errors
    ///
    /// Returns the owning run UUID when the prompt belongs to another run.
    pub fn take_full_if_owned(
        &self,
        prompt_id: &str,
        run_uuid: &str,
    ) -> Result<Option<DeferredEntry>, String> {
        let mut g = self
            .pending
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        match g.get(prompt_id) {
            None => Ok(None),
            Some(e) if e.run_uuid == run_uuid => Ok(g.remove(prompt_id)),
            Some(e) => Err(e.run_uuid.clone()),
        }
    }

    /// Send Deny on every sender whose `entry.run_uuid` matches; remove those entries.
    /// Called during prompt-channel teardown to prevent parked Resolve handler thread leaks.
    ///
    /// WR-03: returns the (host, port) tuples that were drained so the caller
    /// can also clear `PromptDedup` entries for the same connections. Without
    /// this, dedup entries from terminated runs accumulate until daemon
    /// restart (the only `gc_expired` call site is the `prompt_channel`
    /// `gc_tick`, which stops ticking after this thread exits).
    pub fn drain_for_run(&self, run_uuid: &str) -> Vec<(String, u16)> {
        let mut g = self
            .pending
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let to_remove: Vec<String> = g
            .iter()
            .filter(|(_, e)| e.run_uuid == run_uuid)
            .map(|(k, _)| k.clone())
            .collect();
        let mut drained: Vec<(String, u16)> = Vec::with_capacity(to_remove.len());
        for k in to_remove {
            if let Some(entry) = g.remove(&k) {
                let _ = entry.sender.send(guard_core::Verdict::Deny);
                drained.push((entry.host, entry.port));
            }
        }
        drained
    }
}

impl Default for DeferredResolveTable {
    fn default() -> Self {
        Self::new()
    }
}

// raised from 16 -> 32 in v0.3 — deferred-resolve mechanism blocks worker
// threads on user prompts (indefinite hold).
pub const WORKER_THREADS: usize = 32;
pub const ACCEPT_QUEUE_DEPTH: usize = 64;
pub const IPC_STREAM_TIMEOUT: Duration = Duration::from_secs(5);

pub struct PendingSnapshotInput {
    pub input: guard_core::SnapshotBuildInput,
    pub is_tty: bool,
    pub baseline_mode: bool,
    pub prepared_at: std::time::Instant,
}

/// Shared daemon state passed to every worker handler.
///
/// v0.3: extended with `log_writer`, `install_artifact_store`,
/// `prompt_dedup`, `recent_gaps`, `baseline_staging`. All v0.3 handlers access
/// these via an Arc<DaemonState> clone.
pub struct DaemonState {
    // v0.2 fields (preserved)
    pub process_tree: Arc<ProcessTree>,
    pub gap_detector: Arc<GapDetector>,
    pub rule_store: Arc<crate::rule_store::RuleStore>,
    pub curated: Arc<Vec<guard_core::AllowlistEntry>>,
    pub state_dir: std::path::PathBuf,
    // v0.3 additions
    pub install_artifact_store: Arc<InstallArtifactStore>,
    pub log_writer: LogWriter, // already Clone (backed by Arc<channel>)
    pub prompt_dedup: Arc<PromptDedup>,
    pub recent_gaps: Arc<RecentGapsRing>,
    pub baseline_staging: Arc<BaselineStaging>,
    // v0.3 (WARNING #6 fix): snapshot-publication failure flag.
    pub last_snapshot_publish_failed: AtomicBool,
    pub deferred_resolve: Arc<DeferredResolveTable>,
    // v0.5 M004-S01: monotonic startup instant for uptime reporting in Ping.
    pub startup_instant: std::time::Instant,
    pub pending_snapshot_inputs: Arc<Mutex<HashMap<String, PendingSnapshotInput>>>,
    // Issue #31: production accepts only OS- or hardware-mediated signer kinds.
    pub rule_signature_policy: guard_core::RuleSignaturePolicy,
}

impl DaemonState {
    /// Construct daemon state with no-op v0.3 subsystems for tests and
    /// compatibility callers.
    ///
    /// # Panics
    ///
    /// Panics only if the in-memory install artifact store cannot be opened.
    pub fn new(
        process_tree: Arc<ProcessTree>,
        gap_detector: Arc<GapDetector>,
        rule_store: Arc<crate::rule_store::RuleStore>,
        curated: Arc<Vec<guard_core::AllowlistEntry>>,
        state_dir: std::path::PathBuf,
    ) -> Self {
        // v0.2 constructor preserved for backward compat with tests.
        // v0.3 subsystems are stubbed with no-op defaults here so existing
        // ipc_server tests compile without changes. main.rs uses `DaemonState { .. }`
        // struct literal with all fields when constructing the live daemon.
        let install_artifact_store = Arc::new(
            InstallArtifactStore::open_in_memory().expect("in-memory install_artifact_store"),
        );
        let log_writer = LogWriter::noop();
        let prompt_dedup = Arc::new(PromptDedup::new());
        let recent_gaps = Arc::new(RecentGapsRing::new());
        let baseline_staging = Arc::new(BaselineStaging::new());
        Self {
            process_tree,
            gap_detector,
            rule_store,
            curated,
            state_dir,
            install_artifact_store,
            log_writer,
            prompt_dedup,
            recent_gaps,
            baseline_staging,
            last_snapshot_publish_failed: AtomicBool::new(false),
            deferred_resolve: Arc::new(DeferredResolveTable::new()),
            startup_instant: std::time::Instant::now(),
            pending_snapshot_inputs: Arc::new(Mutex::new(HashMap::new())),
            rule_signature_policy: guard_core::RuleSignaturePolicy::Production,
        }
    }

    pub fn db_path(&self) -> std::path::PathBuf {
        guard_core::paths::db_path(&self.state_dir)
    }
}

pub struct IpcServer {
    listener: UnixListener,
    state: Arc<DaemonState>,
}

impl IpcServer {
    /// Bind a fresh listener at `socket_path`. Removes any stale socket file
    /// and sets socket permissions based on the deployment mode:
    ///
    /// - **User mode** (0o600): only the owning user can connect (same-UID).
    /// - **System mode** (0o666): any user can connect; codesign peer auth
    ///   is the authentication layer, not filesystem permissions. Required
    ///   because the daemon runs as `_stt_guard` but CLI/hook run as the user.
    ///
    /// # Errors
    ///
    /// Returns filesystem or socket errors from removing stale sockets,
    /// binding, reading metadata, or setting permissions.
    pub fn bind(socket_path: &Path, state: Arc<DaemonState>) -> std::io::Result<Self> {
        let _ = std::fs::remove_file(socket_path);
        let listener = UnixListener::bind(socket_path)?;
        let mode = if crate::state_dir::is_system_install(&state.state_dir) {
            0o666
        } else {
            0o600
        };
        let mut perms = std::fs::metadata(socket_path)?.permissions();
        perms.set_mode(mode);
        std::fs::set_permissions(socket_path, perms)?;
        Ok(Self { listener, state })
    }

    /// Single-shot accept — used by integration tests.
    ///
    /// # Errors
    ///
    /// Returns listener accept errors.
    pub fn accept_one(&self) -> std::io::Result<()> {
        let (stream, _) = self.listener.accept()?;
        Self::handle(stream, &self.state);
        Ok(())
    }

    /// Run forever — bounded thread pool consumes from a bounded channel.
    /// Takes self by value because the listener and channel senders move into
    /// long-lived workers.
    ///
    /// WARNING fix (v0.2 review): each worker is wrapped in a panic
    /// catcher so a single panicked handler does NOT silently shrink the
    /// worker pool. On panic, the worker is respawned with a fresh `state`
    /// clone and the same channel receiver. Without this, a poisoned `RwLock`
    /// inside `process_tree.write().expect(...)` could panic one worker per
    /// pid; the daemon would silently degrade to N-K concurrency with no
    /// log evidence of the loss.
    ///
    /// # Errors
    ///
    /// Returns listener accept errors.
    pub fn run_forever(self) -> std::io::Result<()> {
        let (tx, rx) = bounded::<UnixStream>(ACCEPT_QUEUE_DEPTH);
        for worker_id in 0..WORKER_THREADS {
            spawn_worker(worker_id, rx.clone(), self.state.clone());
        }
        loop {
            let (stream, _) = self.listener.accept()?;
            // Backpressure: try_send drops the connection on a full queue.
            // The dylib's IPC times out → fork fails-closed.
            match tx.try_send(stream) {
                Ok(()) => {}
                Err(TrySendError::Full(_)) => {
                    warn!(
                        queue_depth = ACCEPT_QUEUE_DEPTH,
                        "accept queue full — dropping connection (fail-closed-at-fork)"
                    );
                }
                Err(TrySendError::Disconnected(_)) => {
                    error!("worker channel disconnected — daemon exiting accept loop");
                    return Ok(());
                }
            }
        }
    }
}

/// WARNING: spawn a worker that catches panics and respawns itself.
/// Lives outside the `IpcServer` impl so the recursive respawn cleanly
/// captures a fresh `Arc<DaemonState>` clone and the same `Receiver`.
fn spawn_worker(
    worker_id: usize,
    rx: crossbeam_channel::Receiver<UnixStream>,
    state: Arc<DaemonState>,
) {
    let _ = std::thread::Builder::new()
        .name(format!("stt-guard-daemon-worker-{worker_id}"))
        .spawn(move || {
            // catch_unwind around the inner loop. AssertUnwindSafe is
            // acceptable here: `IpcServer::handle` is structured so any
            // partial mutation it leaves behind in `DaemonState` is
            // self-recoverable (nodes/runs maps tolerate stale entries
            // until GC sweep). The Arc references themselves are unwind-
            // safe by construction.
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                while let Ok(stream) = rx.recv() {
                    IpcServer::handle(stream, &state);
                }
            }));
            if let Err(panic_payload) = result {
                let msg = if let Some(s) = panic_payload.downcast_ref::<&str>() {
                    (*s).to_string()
                } else if let Some(s) = panic_payload.downcast_ref::<String>() {
                    s.clone()
                } else {
                    "non-string panic payload".to_string()
                };
                error!(worker_id, panic = %msg, "ipc worker panicked — respawning");
                spawn_worker(worker_id, rx, state);
            }
            // Normal exit (rx Disconnected) is silent: the daemon is shutting
            // down and the listener will return Err next accept iteration.
        });
}

impl IpcServer {
    fn handle(mut stream: UnixStream, state: &Arc<DaemonState>) {
        let Some(peer_token) = authenticate_verified_peer(&mut stream) else {
            return;
        };

        let _ = stream.set_read_timeout(Some(IPC_STREAM_TIMEOUT));
        let _ = stream.set_write_timeout(Some(IPC_STREAM_TIMEOUT));

        let Some(kind) = classify_peer_frame(&mut stream, &peer_token) else {
            return;
        };

        if matches!(kind, FrameKind::Tagged(MessageTag::PromptChannelInit)) {
            handle_prompt_channel_init_frame(stream, state);
            return;
        }

        dispatch_peer_frame(&kind, &mut stream, peer_token, state);
    }
}

fn authenticate_verified_peer(stream: &mut UnixStream) -> Option<AuditToken> {
    let peer_id = match authenticate(stream) {
        Ok(id) => id,
        Err(e) => {
            warn!(error = %e, "peer auth failed");
            let _ = write_legacy_err(stream, format!("peer auth: {e}"));
            return None;
        }
    };

    let peer_token = if let Some(k) = peer_id.as_policy_key() {
        *k
    } else {
        warn!("peer authenticated as Unverified — refusing");
        let _ = write_legacy_err(stream, "peer not Verified");
        return None;
    };

    // M006-S02: codesign peer verification.
    if !crate::codesign::should_accept_peer(&peer_token) {
        warn!(
            peer_pid = peer_token.pid(),
            "peer rejected: invalid code signature"
        );
        let _ = write_legacy_err(stream, "codesign verification failed");
        return None;
    }

    Some(peer_token)
}

fn classify_peer_frame(stream: &mut UnixStream, peer_token: &AuditToken) -> Option<FrameKind> {
    Some(match classify_frame(stream) {
        Ok(k) => k,
        Err(DispatchError::Io(e)) if e.kind() == ErrorKind::UnexpectedEof => {
            // Connect-only liveness probe (v0.1 semantics) —
            // benign; no state change, no Reply written.
            debug!(
                peer_pid = peer_token.val[5],
                "benign liveness probe (connect+EOF)"
            );
            return None;
        }
        Err(e) => {
            warn!(error = %e, "classify_frame failed");
            let _ = write_legacy_err(stream, format!("classify: {e}"));
            return None;
        }
    })
}

fn dispatch_peer_frame(
    kind: &FrameKind,
    stream: &mut UnixStream,
    peer_token: AuditToken,
    state: &Arc<DaemonState>,
) {
    match kind {
        FrameKind::LegacyUntagged { first_length_byte } => {
            handle_legacy_register_root(stream, *first_length_byte, peer_token, state);
        }
        FrameKind::Tagged(MessageTag::ForkEvent) => {
            handle_fork_event(stream, peer_token, state);
        }
        FrameKind::Tagged(MessageTag::ExecEvent) => {
            handle_exec_event(stream, peer_token, state);
        }
        FrameKind::Tagged(MessageTag::DylibLoaded) => {
            handle_dylib_loaded(stream, peer_token, state);
        }
        FrameKind::Tagged(MessageTag::PrepareSnapshot) => {
            handle_prepare_snapshot_frame(stream, peer_token, state);
        }
        FrameKind::Tagged(MessageTag::Resolve) => {
            handle_resolve_frame(stream, peer_token, state);
        }
        FrameKind::Tagged(MessageTag::EnvNotPropagatedGap) => {
            handle_env_not_propagated_frame(stream, peer_token, state);
        }
        FrameKind::Tagged(MessageTag::Status) => handle_status_frame(stream, state),
        FrameKind::Tagged(MessageTag::InsertUserRule) => {
            handle_insert_user_rule_frame(stream, state);
        }
        FrameKind::Tagged(MessageTag::ReadInstallArtifacts) => {
            handle_read_install_artifacts_frame(stream, state);
        }
        FrameKind::Tagged(MessageTag::BaselineCommit) => {
            handle_baseline_commit_frame(stream, state);
        }
        FrameKind::Tagged(MessageTag::PromptChannelInit) => unreachable!(),
        FrameKind::Tagged(MessageTag::ListRules) => handle_list_rules_frame(stream, state),
        FrameKind::Tagged(MessageTag::DeleteInstallArtifacts) => {
            handle_delete_install_artifacts_frame(stream, state);
        }
        FrameKind::Tagged(MessageTag::DenyNotify) => handle_deny_notify_frame(stream, state),
        FrameKind::Tagged(MessageTag::ExecBlocked) => handle_exec_blocked_frame(stream, state),
        FrameKind::Tagged(MessageTag::PersistenceWrite) => {
            handle_persistence_write_frame(stream, state);
        }
        FrameKind::Tagged(MessageTag::Ping) => handle_ping_frame(stream, state),
        FrameKind::Tagged(MessageTag::DisableCuratedRule) => {
            handle_disable_curated_rule_frame(stream, state);
        }
        FrameKind::Tagged(MessageTag::EnableCuratedRule) => {
            handle_enable_curated_rule_frame(stream, state);
        }
        FrameKind::Tagged(MessageTag::PrepareSnapshotInputs) => {
            handle_prepare_snapshot_inputs_frame(stream, state);
        }
        FrameKind::Tagged(MessageTag::PublishSignedSnapshot) => {
            handle_publish_signed_snapshot_frame(stream, state);
        }
    }
}

// ============================================================================
// v0.3 — request-reply frame handlers for CLI IPC surface
// ============================================================================

fn handle_status_frame(stream: &mut UnixStream, state: &Arc<DaemonState>) {
    let req: Status = match read_tagged_body(stream, MessageTag::Status) {
        Ok(m) => m,
        Err(e) => {
            warn!(error = %e, "Status decode failed");
            let _ = write_tagged(
                stream,
                MessageTag::Status,
                &StatusReply::err(format!("decode: {e}")),
            );
            return;
        }
    };
    if req.schema_version != IPC_SCHEMA_V3 {
        let _ = write_tagged(
            stream,
            MessageTag::Status,
            &StatusReply::err(format!(
                "schema_version {} != IPC_SCHEMA_V3",
                req.schema_version
            )),
        );
        return;
    }
    let reply = crate::handlers::status::handle_status(state);
    if let Err(e) = write_tagged(stream, MessageTag::Status, &reply) {
        error!(error = %e, "failed to send StatusReply");
    }
}

fn handle_insert_user_rule_frame(stream: &mut UnixStream, state: &Arc<DaemonState>) {
    let req: InsertUserRule = match read_tagged_body(stream, MessageTag::InsertUserRule) {
        Ok(m) => m,
        Err(e) => {
            warn!(error = %e, "InsertUserRule decode failed");
            let _ = write_tagged(
                stream,
                MessageTag::InsertUserRule,
                &InsertUserRuleReply::err(format!("decode: {e}")),
            );
            return;
        }
    };
    if !matches!(req.schema_version, IPC_SCHEMA_V3 | guard_ipc::IPC_SCHEMA_V5) {
        let _ = write_tagged(
            stream,
            MessageTag::InsertUserRule,
            &InsertUserRuleReply::err(format!(
                "schema_version {} not supported for InsertUserRule",
                req.schema_version
            )),
        );
        return;
    }
    let reply = crate::handlers::insert_user_rule::handle_insert_user_rule(
        &req,
        &state.rule_store,
        state.rule_signature_policy,
    );
    if let Err(e) = write_tagged(stream, MessageTag::InsertUserRule, &reply) {
        error!(error = %e, "failed to send InsertUserRuleReply");
    }
}

fn handle_read_install_artifacts_frame(stream: &mut UnixStream, state: &Arc<DaemonState>) {
    let req: ReadInstallArtifacts = match read_tagged_body(stream, MessageTag::ReadInstallArtifacts)
    {
        Ok(m) => m,
        Err(e) => {
            warn!(error = %e, "ReadInstallArtifacts decode failed");
            let _ = write_tagged(
                stream,
                MessageTag::ReadInstallArtifacts,
                &ReadInstallArtifactsReply::err(format!("decode: {e}")),
            );
            return;
        }
    };
    if req.schema_version != IPC_SCHEMA_V3 {
        let _ = write_tagged(
            stream,
            MessageTag::ReadInstallArtifacts,
            &ReadInstallArtifactsReply::err(format!(
                "schema_version {} != IPC_SCHEMA_V3",
                req.schema_version
            )),
        );
        return;
    }
    let reply = crate::handlers::read_install_artifacts::handle_read_install_artifacts(
        &state.install_artifact_store,
    );
    if let Err(e) = write_tagged(stream, MessageTag::ReadInstallArtifacts, &reply) {
        error!(error = %e, "failed to send ReadInstallArtifactsReply");
    }
}

fn handle_baseline_commit_frame(stream: &mut UnixStream, state: &Arc<DaemonState>) {
    let req: BaselineCommit = match read_tagged_body(stream, MessageTag::BaselineCommit) {
        Ok(m) => m,
        Err(e) => {
            warn!(error = %e, "BaselineCommit decode failed");
            let _ = write_tagged(
                stream,
                MessageTag::BaselineCommit,
                &BaselineCommitReply::err(format!("decode: {e}")),
            );
            return;
        }
    };
    if req.schema_version != IPC_SCHEMA_V3 {
        let _ = write_tagged(
            stream,
            MessageTag::BaselineCommit,
            &BaselineCommitReply::err(format!(
                "schema_version {} != IPC_SCHEMA_V3",
                req.schema_version
            )),
        );
        return;
    }
    let reply = crate::handlers::baseline_commit::handle_baseline_commit(&req, state);
    if let Err(e) = write_tagged(stream, MessageTag::BaselineCommit, &reply) {
        error!(error = %e, "failed to send BaselineCommitReply");
    }
}

// ============================================================================
// v0.7 — management-IPC frame handlers (ListRules /
// DeleteInstallArtifacts). Each is a verbatim copy of the
// `handle_read_install_artifacts_frame` shape with type names swapped.
// Both enforce `schema_version == IPC_SCHEMA_V3`.
// ============================================================================

fn handle_list_rules_frame(stream: &mut UnixStream, state: &Arc<DaemonState>) {
    let req: ListRules = match read_tagged_body(stream, MessageTag::ListRules) {
        Ok(m) => m,
        Err(e) => {
            warn!(error = %e, "ListRules decode failed");
            let _ = write_tagged(
                stream,
                MessageTag::ListRules,
                &ListRulesReply::err(format!("decode: {e}")),
            );
            return;
        }
    };
    if req.schema_version != IPC_SCHEMA_V3 {
        let _ = write_tagged(
            stream,
            MessageTag::ListRules,
            &ListRulesReply::err(format!(
                "schema_version {} != IPC_SCHEMA_V3",
                req.schema_version
            )),
        );
        return;
    }
    let reply = crate::handlers::list_rules::handle_list_rules(
        &req,
        &state.rule_store,
        state.curated.as_ref(),
    );
    if let Err(e) = write_tagged(stream, MessageTag::ListRules, &reply) {
        error!(error = %e, "failed to send ListRulesReply");
    }
}

fn handle_delete_install_artifacts_frame(stream: &mut UnixStream, state: &Arc<DaemonState>) {
    let req: DeleteInstallArtifacts =
        match read_tagged_body(stream, MessageTag::DeleteInstallArtifacts) {
            Ok(m) => m,
            Err(e) => {
                warn!(error = %e, "DeleteInstallArtifacts decode failed");
                let _ = write_tagged(
                    stream,
                    MessageTag::DeleteInstallArtifacts,
                    &DeleteInstallArtifactsReply::err(format!("decode: {e}")),
                );
                return;
            }
        };
    if req.schema_version != IPC_SCHEMA_V3 {
        let _ = write_tagged(
            stream,
            MessageTag::DeleteInstallArtifacts,
            &DeleteInstallArtifactsReply::err(format!(
                "schema_version {} != IPC_SCHEMA_V3",
                req.schema_version
            )),
        );
        return;
    }
    let reply = crate::handlers::delete_install_artifacts::handle_delete_install_artifacts(
        &req,
        &state.install_artifact_store,
    );
    if let Err(e) = write_tagged(stream, MessageTag::DeleteInstallArtifacts, &reply) {
        error!(error = %e, "failed to send DeleteInstallArtifactsReply");
    }
}

// ============================================================================
// v0.3 — DenyNotify frame handler
// ============================================================================

struct DenyNotifyLogContext {
    run_uuid: String,
    process: crate::log_writer::jsonl_row::ProcessCtxLog,
    parent: crate::log_writer::jsonl_row::ProcessCtxLog,
    root: crate::log_writer::jsonl_row::RootCtxLog,
    package_context: Option<guard_ipc::PackageContext>,
}

fn argv_for_binary_path(binary_path: &str) -> Vec<String> {
    if binary_path.is_empty() {
        vec![]
    } else {
        vec![binary_path.to_string()]
    }
}

fn process_log_context(
    audit_token: &AuditToken,
    binary_path: &str,
) -> crate::log_writer::jsonl_row::ProcessCtxLog {
    crate::log_writer::jsonl_row::ProcessCtxLog {
        pid: audit_token.val[5],
        pidversion: audit_token.val[7],
        argv: argv_for_binary_path(binary_path),
        cwd: String::new(),
    }
}

fn empty_process_log_context(
    audit_token: &AuditToken,
) -> crate::log_writer::jsonl_row::ProcessCtxLog {
    crate::log_writer::jsonl_row::ProcessCtxLog {
        pid: audit_token.val[5],
        pidversion: audit_token.val[7],
        argv: vec![],
        cwd: String::new(),
    }
}

fn deny_notify_parent_context(
    state: &DaemonState,
    node: &crate::tracked::ProcessNode,
) -> crate::log_writer::jsonl_row::ProcessCtxLog {
    node.parent_audit_token
        .as_ref()
        .and_then(|parent_token| state.process_tree.get_node(parent_token))
        .map_or(
            crate::log_writer::jsonl_row::ProcessCtxLog {
                pid: 0,
                pidversion: 0,
                argv: vec![],
                cwd: String::new(),
            },
            |parent_node| process_log_context(&parent_node.audit_token, &parent_node.binary_path),
        )
}

fn deny_notify_root_context(
    state: &DaemonState,
    node: &crate::tracked::ProcessNode,
) -> crate::log_writer::jsonl_row::RootCtxLog {
    let root_argv = state
        .process_tree
        .get_node(&node.tracked_root)
        .map(|root_node| argv_for_binary_path(&root_node.binary_path))
        .unwrap_or_default();

    crate::log_writer::jsonl_row::RootCtxLog {
        audit_token: node.tracked_root.val,
        argv: root_argv,
    }
}

fn deny_notify_log_context(state: &DaemonState, sender_token: &AuditToken) -> DenyNotifyLogContext {
    let Some(node) = state.process_tree.get_node(sender_token) else {
        return DenyNotifyLogContext {
            run_uuid: String::new(),
            process: empty_process_log_context(sender_token),
            parent: crate::log_writer::jsonl_row::ProcessCtxLog {
                pid: 0,
                pidversion: 0,
                argv: vec![],
                cwd: String::new(),
            },
            root: crate::log_writer::jsonl_row::RootCtxLog {
                audit_token: [0; 8],
                argv: vec![],
            },
            package_context: None,
        };
    };

    let root = deny_notify_root_context(state, &node);
    let package_context = crate::log_writer::package_context::infer_package_context(
        &state.process_tree,
        sender_token,
        &root.argv.join(" "),
    );

    DenyNotifyLogContext {
        run_uuid: node.run_uuid.clone(),
        process: process_log_context(sender_token, &node.binary_path),
        parent: deny_notify_parent_context(state, &node),
        root,
        package_context,
    }
}

fn enrich_deny_notify_decision(
    decision: &mut crate::log_writer::jsonl_row::Decision,
    req: &DenyNotify,
) {
    if !matches!(req.source_kind.as_str(), "confirmed-deny" | "suspect-deny") {
        return;
    }

    let Some(host) = &req.dest_host else {
        return;
    };

    let curated = match crate::curated::load_curated() {
        Ok(c) => c,
        Err(e) => {
            warn!(error = %e, "failed to load curated rules for intel enrichment");
            Vec::new()
        }
    };
    let intel = crate::log_writer::enrich_from_entries(host.as_bytes(), &curated);
    if !intel.is_empty() {
        decision.intel = Some(intel);
    }
}

fn log_previously_approved_deny_notify(req: &DenyNotify, state: &DaemonState) {
    if req.source_kind != "confirmed-deny" {
        return;
    }

    let Some(host) = &req.dest_host else {
        return;
    };

    let user_approved = state.rule_store.has_user_allow_for(host).unwrap_or(false);
    if user_approved {
        info!(
            dest_host = %host,
            "DenyNotify: confirmed-deny overrides user-allow — previously approved host now suspended"
        );
    }
}

fn handle_deny_notify_frame(stream: &mut UnixStream, state: &Arc<DaemonState>) {
    use crate::log_writer::jsonl_row::{Decision, JSONL_SCHEMA_VERSION, LogRow, now_rfc3339};

    let req: DenyNotify = match read_tagged_body(stream, MessageTag::DenyNotify) {
        Ok(m) => m,
        Err(e) => {
            warn!(error = %e, "DenyNotify decode failed");
            let _ = write_tagged(
                stream,
                MessageTag::DenyNotify,
                &DenyNotifyAck::err(format!("decode: {e}")),
            );
            return;
        }
    };
    if req.schema_version != IPC_SCHEMA_V4 {
        let _ = write_tagged(
            stream,
            MessageTag::DenyNotify,
            &DenyNotifyAck::err(format!(
                "schema_version {} != IPC_SCHEMA_V4",
                req.schema_version
            )),
        );
        return;
    }

    let sender_token: guard_core::AuditToken = req.audit_token.into();
    let log_context = deny_notify_log_context(state, &sender_token);

    let mut decision = Decision {
        schema_version: JSONL_SCHEMA_VERSION,
        ts: now_rfc3339(),
        verdict: "Deny",
        dest_host: req.dest_host.clone().unwrap_or_default(),
        dest_port: req.dest_port,
        dest_ip: req.dest_ip.clone(),
        run_uuid: log_context.run_uuid,
        source_kind: if req.source_kind.is_empty() {
            "hook_deny".into()
        } else {
            req.source_kind.clone()
        },
        source_locator: Some(req.source_surface.clone()),
        process: log_context.process,
        parent: log_context.parent,
        root: log_context.root,
        package_context: log_context.package_context,
        intel: None,
    };

    enrich_deny_notify_decision(&mut decision, &req);
    log_previously_approved_deny_notify(&req, state);

    state.log_writer.send(LogRow::Block(decision));

    debug!(
        dest_host = ?req.dest_host,
        dest_port = req.dest_port,
        source_surface = %req.source_surface,
        "DenyNotify logged"
    );

    if let Err(e) = write_tagged(stream, MessageTag::DenyNotify, &DenyNotifyAck::ok()) {
        error!(error = %e, "failed to send DenyNotifyAck");
    }
}

// ============================================================================
// v0.4 M003-S02 — ExecBlocked frame handler
// ============================================================================

fn handle_exec_blocked_frame(stream: &mut UnixStream, state: &Arc<DaemonState>) {
    use crate::log_writer::jsonl_row::{JSONL_SCHEMA_VERSION, LogRow, ProcessCtxLog, now_rfc3339};

    let req: ExecBlocked = match read_tagged_body(stream, MessageTag::ExecBlocked) {
        Ok(m) => m,
        Err(e) => {
            warn!(error = %e, "ExecBlocked decode failed");
            let _ = write_tagged(
                stream,
                MessageTag::ExecBlocked,
                &ExecBlockedAck::err(format!("decode: {e}")),
            );
            return;
        }
    };
    if req.schema_version != IPC_SCHEMA_V4 {
        let _ = write_tagged(
            stream,
            MessageTag::ExecBlocked,
            &ExecBlockedAck::err(format!(
                "schema_version {} != IPC_SCHEMA_V4",
                req.schema_version
            )),
        );
        return;
    }

    let target_path = String::from_utf8_lossy(&req.target_path).to_string();
    let sender_token: guard_core::AuditToken = req.audit_token.into();
    let node_opt = state.process_tree.get_node(&sender_token);

    let (run_uuid, process_ctx) = if let Some(ref node) = node_opt {
        let process_ctx = ProcessCtxLog {
            pid: sender_token.val[5],
            pidversion: sender_token.val[7],
            argv: if node.binary_path.is_empty() {
                vec![]
            } else {
                vec![node.binary_path.clone()]
            },
            cwd: String::new(),
        };
        (node.run_uuid.clone(), process_ctx)
    } else {
        let process_ctx = ProcessCtxLog {
            pid: sender_token.val[5],
            pidversion: sender_token.val[7],
            argv: vec![],
            cwd: String::new(),
        };
        (String::new(), process_ctx)
    };

    let gap = crate::log_writer::jsonl_row::GapRecord {
        schema_version: JSONL_SCHEMA_VERSION,
        ts: now_rfc3339(),
        run_uuid,
        gap_kind: "exec-blocked",
        process: process_ctx,
        binary_path: Some(target_path.clone()),
    };

    state.log_writer.send(LogRow::Gap(gap));

    info!(
        target_path = %target_path,
        reason = %req.reason,
        "exec blocked"
    );

    if let Err(e) = write_tagged(stream, MessageTag::ExecBlocked, &ExecBlockedAck::ok()) {
        error!(error = %e, "failed to send ExecBlockedAck");
    }
}

// ============================================================================
// v0.4 M003-S04 — PersistenceWrite frame handler
// ============================================================================

fn handle_persistence_write_frame(stream: &mut UnixStream, state: &Arc<DaemonState>) {
    use crate::log_writer::jsonl_row::{JSONL_SCHEMA_VERSION, LogRow, ProcessCtxLog, now_rfc3339};

    let req: PersistenceWrite = match read_tagged_body(stream, MessageTag::PersistenceWrite) {
        Ok(m) => m,
        Err(e) => {
            warn!(error = %e, "PersistenceWrite decode failed");
            let _ = write_tagged(
                stream,
                MessageTag::PersistenceWrite,
                &PersistenceWriteAck::err(format!("decode: {e}")),
            );
            return;
        }
    };
    if req.schema_version != IPC_SCHEMA_V4 {
        let _ = write_tagged(
            stream,
            MessageTag::PersistenceWrite,
            &PersistenceWriteAck::err(format!(
                "schema_version {} != IPC_SCHEMA_V4",
                req.schema_version
            )),
        );
        return;
    }

    let target_path = String::from_utf8_lossy(&req.target_path).to_string();
    let sender_token: guard_core::AuditToken = req.audit_token.into();
    let node_opt = state.process_tree.get_node(&sender_token);

    let (run_uuid, process_ctx) = if let Some(ref node) = node_opt {
        let process_ctx = ProcessCtxLog {
            pid: sender_token.val[5],
            pidversion: sender_token.val[7],
            argv: if node.binary_path.is_empty() {
                vec![]
            } else {
                vec![node.binary_path.clone()]
            },
            cwd: String::new(),
        };
        (node.run_uuid.clone(), process_ctx)
    } else {
        let process_ctx = ProcessCtxLog {
            pid: sender_token.val[5],
            pidversion: sender_token.val[7],
            argv: vec![],
            cwd: String::new(),
        };
        (String::new(), process_ctx)
    };

    let gap = crate::log_writer::jsonl_row::GapRecord {
        schema_version: JSONL_SCHEMA_VERSION,
        ts: now_rfc3339(),
        run_uuid,
        gap_kind: "persistence-write",
        process: process_ctx,
        binary_path: Some(target_path.clone()),
    };

    state.log_writer.send(LogRow::Gap(gap));

    info!(
        target_path = %target_path,
        category = %req.category,
        "persistence write detected"
    );

    if let Err(e) = write_tagged(
        stream,
        MessageTag::PersistenceWrite,
        &PersistenceWriteAck::ok(),
    ) {
        error!(error = %e, "failed to send PersistenceWriteAck");
    }
}

// ============================================================================
// v0.5 M004-S01 — Ping frame handler (watchdog liveness)
// ============================================================================

fn handle_ping_frame(stream: &mut UnixStream, state: &Arc<DaemonState>) {
    let _req: Ping = match read_tagged_body(stream, MessageTag::Ping) {
        Ok(m) => m,
        Err(e) => {
            warn!(error = %e, "Ping decode failed");
            let _ = write_tagged(
                stream,
                MessageTag::Ping,
                &PingReply::err(format!("decode: {e}")),
            );
            return;
        }
    };
    let pid = std::process::id();
    let uptime_secs = state.startup_instant.elapsed().as_secs();
    if let Err(e) = write_tagged(stream, MessageTag::Ping, &PingReply::pong(pid, uptime_secs)) {
        error!(error = %e, "failed to send PingReply");
    }
}

// ============================================================================
// v1.0 — DisableCuratedRule / EnableCuratedRule frame handlers
// ============================================================================

fn handle_disable_curated_rule_frame(stream: &mut UnixStream, state: &Arc<DaemonState>) {
    let req: DisableCuratedRule = match read_tagged_body(stream, MessageTag::DisableCuratedRule) {
        Ok(m) => m,
        Err(e) => {
            warn!(error = %e, "DisableCuratedRule decode failed");
            let _ = write_tagged(
                stream,
                MessageTag::DisableCuratedRule,
                &DisableCuratedRuleReply::err(format!("decode: {e}")),
            );
            return;
        }
    };
    if !matches!(req.schema_version, IPC_SCHEMA_V3 | IPC_SCHEMA_V5) {
        let _ = write_tagged(
            stream,
            MessageTag::DisableCuratedRule,
            &DisableCuratedRuleReply::err(format!(
                "schema_version {} not supported for DisableCuratedRule",
                req.schema_version
            )),
        );
        return;
    }
    let reply = crate::handlers::disable_curated_rule::handle_disable_curated_rule(
        &req,
        &state.rule_store,
        state.curated.as_ref(),
        state.rule_signature_policy,
    );
    if let Err(e) = write_tagged(stream, MessageTag::DisableCuratedRule, &reply) {
        error!(error = %e, "failed to send DisableCuratedRuleReply");
    }
}

fn handle_enable_curated_rule_frame(stream: &mut UnixStream, state: &Arc<DaemonState>) {
    let req: EnableCuratedRule = match read_tagged_body(stream, MessageTag::EnableCuratedRule) {
        Ok(m) => m,
        Err(e) => {
            warn!(error = %e, "EnableCuratedRule decode failed");
            let _ = write_tagged(
                stream,
                MessageTag::EnableCuratedRule,
                &EnableCuratedRuleReply::err(format!("decode: {e}")),
            );
            return;
        }
    };
    if !matches!(req.schema_version, IPC_SCHEMA_V3 | IPC_SCHEMA_V5) {
        let _ = write_tagged(
            stream,
            MessageTag::EnableCuratedRule,
            &EnableCuratedRuleReply::err(format!(
                "schema_version {} not supported for EnableCuratedRule",
                req.schema_version
            )),
        );
        return;
    }
    let reply = crate::handlers::enable_curated_rule::handle_enable_curated_rule(
        &req,
        &state.rule_store,
        state.rule_signature_policy,
    );
    if let Err(e) = write_tagged(stream, MessageTag::EnableCuratedRule, &reply) {
        error!(error = %e, "failed to send EnableCuratedRuleReply");
    }
}

// ============================================================================
// v0.3 — PromptChannelInit frame handler (spawn-and-detach)
// ============================================================================

/// Handle a `PromptChannelInit` tagged frame.
///
/// Takes `stream` BY VALUE (moved out of the `handle` dispatch loop via `return`
/// so the dispatch loop does NOT drop it).  The function:
///   1. Reads the `PromptChannelInit` body.
///   2. Validates `schema_version` + `run_uuid` + cap.
///   3. Writes Ok/Err Ack.
///   4. On Ok: spawns a dedicated "stt-guard-daemon-prompt-{uuid8}" thread that calls
///      `handlers::prompt_channel::run(stream, state, run_uuid)`.
///      Pitfall 4: the dedicated thread is NOT on the worker pool.
fn handle_prompt_channel_init_frame(mut stream: UnixStream, state: &Arc<DaemonState>) {
    let init: PromptChannelInit = match read_tagged_body(&mut stream, MessageTag::PromptChannelInit)
    {
        Ok(m) => m,
        Err(e) => {
            let _ = write_tagged(
                &mut stream,
                MessageTag::PromptChannelInit,
                &PromptChannelInitAck::err(format!("decode: {e}")),
            );
            return;
        }
    };
    if init.schema_version != IPC_SCHEMA_V3 {
        let _ = write_tagged(
            &mut stream,
            MessageTag::PromptChannelInit,
            &PromptChannelInitAck::err(format!("schema_version {} != V3", init.schema_version)),
        );
        return;
    }
    if state.process_tree.get_run(&init.run_uuid).is_none() {
        let _ = write_tagged(
            &mut stream,
            MessageTag::PromptChannelInit,
            &PromptChannelInitAck::err(format!("unknown run_uuid {}", init.run_uuid)),
        );
        return;
    }
    // BLOCKER — cap gate.
    let current = state.process_tree.prompt_channels_len();
    if current >= crate::handlers::prompt_channel::MAX_CONCURRENT_CHANNELS {
        let _ = write_tagged(
            &mut stream,
            MessageTag::PromptChannelInit,
            &PromptChannelInitAck::err(format!(
                "max concurrent channels reached ({})",
                crate::handlers::prompt_channel::MAX_CONCURRENT_CHANNELS
            )),
        );
        return;
    }
    // CR-03: spawn FIRST, ack only on spawn success. Previously the OK ack
    // was written before `std::thread::Builder::new().spawn(...)`. If the
    // spawn failed (resource exhaustion, FD pressure, pthread_create error)
    // the client received a green ack but no thread would ever consume the
    // stream — the run's prompt UI loop would block on the next read forever.
    //
    // Pitfall 4: spawn-and-detach — dedicated thread, NOT a worker pool slot.
    // The thread takes ownership of `stream` on success; on spawn failure we
    // need our own writeable handle for the err-Ack, so clone the stream
    // up-front and use the clone for the ack path.
    let ack_stream = match stream.try_clone() {
        Ok(s) => s,
        Err(e) => {
            // Best-effort err-Ack on the original stream before giving up.
            let _ = write_tagged(
                &mut stream,
                MessageTag::PromptChannelInit,
                &PromptChannelInitAck::err(format!("try_clone: {e}")),
            );
            return;
        }
    };
    let state_clone = state.clone();
    let run_uuid = init.run_uuid.clone();
    let _ = stream.set_read_timeout(None);
    let _ = stream.set_write_timeout(None);
    let spawn_result = std::thread::Builder::new()
        .name(format!(
            "stt-guard-daemon-prompt-{}",
            &run_uuid[..8.min(run_uuid.len())]
        ))
        .spawn(move || crate::handlers::prompt_channel::run(stream, &state_clone, &run_uuid));

    let mut ack_stream = ack_stream;
    match spawn_result {
        Ok(_) => {
            if let Err(e) = write_tagged(
                &mut ack_stream,
                MessageTag::PromptChannelInit,
                &PromptChannelInitAck::ok(),
            ) {
                error!(error = %e, "failed to send PromptChannelInit Ok Ack");
            }
        }
        Err(e) => {
            error!(error = %e, "failed to spawn prompt_channel thread");
            let _ = write_tagged(
                &mut ack_stream,
                MessageTag::PromptChannelInit,
                &PromptChannelInitAck::err(format!("spawn failed: {e}")),
            );
        }
    }
}

/// Write a v0.1 `Reply::Err` frame as a fallback for diagnostic responses
/// when we don't yet know which message type the peer was sending.
fn write_legacy_err(stream: &mut UnixStream, msg: impl Into<String>) -> Result<(), IpcError> {
    write_frame(stream, &Reply::err(msg))
}

fn handle_legacy_register_root(
    stream: &mut UnixStream,
    first_length_byte: u8,
    peer_token: AuditToken,
    state: &Arc<DaemonState>,
) {
    // Reconstruct the full length prefix (4 bytes big-endian) by reading 3
    // more bytes and prepending the byte we already consumed.
    let mut rest = [0u8; 3];
    if let Err(e) = stream.read_exact(&mut rest) {
        warn!(error = %e, "legacy register read failed");
        return;
    }
    let mut len_bytes = [0u8; 4];
    len_bytes[0] = first_length_byte;
    len_bytes[1..].copy_from_slice(&rest);
    let body_len = u32::from_be_bytes(len_bytes) as usize;
    // Bound check: MAX_FRAME_BYTES (64 KiB) per guard-ipc::frame.
    if body_len > 64 * 1024 {
        warn!(body_len, "legacy register frame too large");
        let _ = write_legacy_err(stream, format!("frame too large: {body_len}"));
        return;
    }
    let mut body = vec![0u8; body_len];
    if let Err(e) = stream.read_exact(&mut body) {
        warn!(error = %e, "legacy register body read failed");
        return;
    }
    let msg: RegisterRoot = match ciborium::de::from_reader(body.as_slice()) {
        Ok(m) => m,
        Err(e) => {
            warn!(error = %e, "legacy register decode failed");
            let _ = write_legacy_err(stream, format!("decode: {e}"));
            return;
        }
    };
    // ENF-08 + RegisterRoot asymmetry:
    // RegisterRoot is a DELEGATION operation: the CLI (the connecting peer)
    // is vouching for an EXTERNAL process (the wrapped child it just spawned).
    // The wire-claimed token is the child's audit token, obtained by the CLI
    // through guard-os' process-audit-token capability.
    //
    // Unlike fork/exec IPC (where the dylib in process X should not be able
    // to impersonate process Y), RegisterRoot is an explicit CLI-to-daemon
    // delegation: the CLI is intentionally naming a different process as root.
    //
    // Strategy (REGISTER-01):
    //   - If wire_pid == kernel_pid: the CLI is registering itself — use
    //     peer_token directly (same process, no delegation needed).
    //   - If wire_pid != kernel_pid: the CLI is registering the child's token.
    //     We accept the WIRE-CLAIMED token (the child's audit token from the
    //     wire) rather than peer_token (the CLI's own kernel token). This
    //     ensures the child's dylib can later authenticate successfully as a
    //     tracked peer. Log at INFO level so the delegation is auditable.
    //
    // Security note: the socket is mode 0600 (owner-only). A malicious local
    // process could abuse this to register arbitrary process tokens — but the
    // trust boundary for v1 is user-space only (no privilege boundary between
    // the CLI and the daemon). Tracking grants no network-enforcement privilege
    // (allow/deny comes from the snapshot); it only arms the gap detector.
    let wire_pid = msg.audit_token.val[5];
    let kernel_pid = peer_token.val[5];
    let registration_token = if wire_pid == kernel_pid {
        peer_token
    } else {
        // WR-08: even though the v1 trust boundary is same-uid only, the
        // delegation arm widens the attack surface — a same-uid process can
        // register some OTHER user's pid as a tracked root, which grants no
        // enforcement privilege but corrupts the gap-detector / process-tree
        // coverage for that pid's children. Sanity-check that the wire pid
        // exists in the OS process table AND has the same uid as the
        // connecting CLI's kernel peer token; refuse on mismatch. In a
        // hardened system install the daemon runs as `_stt_guard`, while
        // wrapped children run as the invoking user.
        if !verify_wire_pid_matches_token(
            libc::pid_t::try_from(wire_pid).unwrap_or(-1),
            &peer_token.val,
            msg.audit_token.val[7],
        ) {
            warn!(
                kernel_pid,
                wire_pid, "RegisterRoot: refusing cross-uid or non-existent wire pid (WR-08)"
            );
            let _ = write_legacy_err(stream, format!("WR-08: refusing wire pid {wire_pid}"));
            return;
        }
        // REGISTER-01: CLI is registering a child process's token.
        info!(
            kernel_pid,
            wire_pid, "RegisterRoot: CLI delegating child registration (REGISTER-01)"
        );
        // Use the full wire-claimed audit token obtained by the CLI.
        msg.audit_token.into()
    };
    // v0.2: insert_root replaces TrackedRoots::insert. Modern CLIs include
    // the run_uuid from PrepareSnapshot so prompt/status paths can associate
    // the child root with the interactive run. Older V1 clients omit it and
    // keep the historical empty-run placeholder behavior.
    let run_uuid = msg.run_uuid.clone().unwrap_or_default();
    let inserted =
        state
            .process_tree
            .insert_root(registration_token, run_uuid.clone(), String::new());
    if let Some(run_uuid) = msg.run_uuid.as_deref() {
        state
            .process_tree
            .bind_run_root(run_uuid, registration_token);
    }
    let captured = crate::env_capture::extract_pm_env(&msg.pm_env);
    if !captured.is_empty() {
        state
            .process_tree
            .set_pm_env_snapshot(&registration_token, captured);
    }
    info!(
        pid = registration_token.val[5],
        pidversion = registration_token.val[7],
        run_uuid = %run_uuid,
        inserted,
        pm_env_pairs = msg.pm_env.len(),
        "registered tracked root"
    );
    if let Err(e) = write_frame(stream, &Reply::ack()) {
        error!(error = %e, "failed to send Ack");
    }
}

/// WR-08 + TREE-07: defense-in-depth for the REGISTER-01 delegation path.
///
/// Checks:
///   (a) wire pid exists in the OS process table
///   (b) owned by a uid-bearing field in the connecting peer's kernel token
///   (c) TREE-07: wire-claimed pidversion matches the OS pidversion for that
///       pid. This closes the PID-reuse race: if a child dies and its PID is
///       recycled between the CLI's lookup and this verification, the recycled
///       process has a different pidversion and registration is rejected.
///
/// The OS pidversion lookup may fail if the platform does not expose it or
/// denies access. In that case the function falls back to uid-only validation
/// (the v0.2 behaviour).
fn verify_wire_pid_matches_token(
    wire_pid: libc::pid_t,
    token_val: &[u32; 8],
    wire_pidversion: u32,
) -> bool {
    // Step 1: uid check via guard-os process inspection.
    let uid_ok = match process_uid(wire_pid) {
        Ok(proc_uid) => {
            let uid_ok =
                token_val[0] == proc_uid || token_val[1] == proc_uid || token_val[3] == proc_uid;
            if !uid_ok {
                warn!(
                    wire_pid,
                    proc_uid,
                    token0 = token_val[0],
                    token1 = token_val[1],
                    token3 = token_val[3],
                    "WR-08: wire pid uid did not match peer token uid fields"
                );
            }
            uid_ok
        }
        Err(err) => {
            warn!(
                wire_pid,
                error = %err,
                "WR-08: process uid lookup failed for wire pid"
            );
            pid_exists(wire_pid)
        }
    };
    if !uid_ok {
        return false;
    }

    // Step 2 (TREE-07): cross-check pidversion through guard-os.
    // If the lookup fails, fall through and accept uid-only validation.
    if wire_pidversion != 0 {
        if let Some(actual_pidversion) = kernel_pidversion(wire_pid) {
            if actual_pidversion != wire_pidversion {
                warn!(
                    wire_pid,
                    wire_pidversion,
                    kernel_pidversion = actual_pidversion,
                    "TREE-07: wire pidversion mismatch — possible PID reuse"
                );
                return false;
            }
        }
    }

    true
}

fn pid_exists(pid: libc::pid_t) -> bool {
    let rc = unsafe { libc::kill(pid, 0) };
    if rc == 0 {
        return true;
    }
    std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM)
}

fn max_frame_bytes_for_tag(tag: MessageTag) -> u32 {
    match tag {
        MessageTag::PrepareSnapshotInputs | MessageTag::PublishSignedSnapshot => {
            guard_ipc::frame::MAX_SNAPSHOT_FRAME_BYTES
        }
        _ => guard_ipc::frame::MAX_FRAME_BYTES,
    }
}

fn read_tagged_body<T>(stream: &mut UnixStream, tag: MessageTag) -> Result<T, IpcError>
where
    T: serde::de::DeserializeOwned,
{
    guard_ipc::frame::read_frame_with_limit(stream, max_frame_bytes_for_tag(tag))
}

fn write_tagged<T>(stream: &mut UnixStream, tag: MessageTag, msg: &T) -> Result<(), IpcError>
where
    T: serde::Serialize,
{
    if let Err(e) = stream.write_all(&[tag.as_byte()]) {
        return Err(IpcError::Io(e));
    }
    guard_ipc::frame::write_frame_with_limit(stream, msg, max_frame_bytes_for_tag(tag))
}

fn handle_fork_event(stream: &mut UnixStream, peer_token: AuditToken, state: &Arc<DaemonState>) {
    let ev: ForkEvent = match read_tagged_body(stream, MessageTag::ForkEvent) {
        Ok(m) => m,
        Err(e) => {
            warn!(error = %e, "fork event decode failed");
            let _ = write_tagged(
                stream,
                MessageTag::ForkEvent,
                &ForkAck::err(format!("decode: {e}")),
            );
            return;
        }
    };
    if ev.schema_version != IPC_SCHEMA_V2 {
        let _ = write_tagged(
            stream,
            MessageTag::ForkEvent,
            &ForkAck::err(format!(
                "schema_version {} != IPC_SCHEMA_V2",
                ev.schema_version
            )),
        );
        return;
    }
    // BLOCKER-02 fix: verify the peer is in the tracked tree BEFORE recording
    // a fork. Without this gate, a stray DYLD_INSERT_LIBRARIES injection into
    // a process that is NOT under `stt-guard wrap` would trigger ForkEvent IPC
    // for every child the parent forks; the daemon would call `record_fork`
    // (which fails with `ParentNotFound`), the dylib would receive
    // `ForkAck::Err`, and `replace_fork.rs::guard_fork` would fail-closed
    // (kill the child + EAGAIN). Net effect on a non-tracked parent: every
    // fork it ever makes is killed — a self-DoS attack surface.
    //
    // Reply with the dedicated `untracked-peer` message so the dylib can
    // distinguish "peer not in tree, ignore me, do not fail-closed" from a
    // real daemon-side rejection. See replace_fork.rs for the matching
    // client-side handling.
    if !state.process_tree.is_tracked(&peer_token) {
        debug!(
            peer_pid = peer_token.val[5],
            "ForkEvent from untracked peer; ignoring (peer is not under stt-guard wrap)"
        );
        let _ = write_tagged(
            stream,
            MessageTag::ForkEvent,
            &ForkAck::err("untracked peer; ignoring fork event"),
        );
        return;
    }
    // ENF-08: trust peer-auth, not wire-claimed parent.
    let wire_parent_pid = ev.parent_audit_token.val[5];
    let kernel_pid = peer_token.val[5];
    if wire_parent_pid != kernel_pid {
        // WARNING-09: escalate to error — see handle_legacy_register_root
        // for the full rationale.
        error!(
            wire_parent_pid,
            kernel_pid,
            "ENF-08 violation: ForkEvent wire-claimed parent disagrees with peer-auth; trusting peer-auth"
        );
    }
    // Construct child audit token from wire pid + pidversion.
    // The kernel-sourced peer token tells us the parent; the wire tells us the
    // child's identity.
    let child = AuditToken {
        val: [
            0,
            0,
            0,
            0,
            0,
            u32::try_from(ev.child_pid).unwrap_or(0),
            0,
            ev.child_pidversion,
        ],
    };
    let result = state.process_tree.record_fork(peer_token, child);
    let recorded_ok = result.is_ok();
    let reply = match result {
        Ok(()) => ForkAck::ok(),
        Err(e) => ForkAck::err(format!("record_fork: {e}")),
    };
    // WARNING-04 fix: after a successful fork, if the CHILD is hardened-
    // runtime, arm a gap detector against the child's audit token. The
    // existing exec-time arming (at handle_exec_event) only fires for the
    // calling process (peer_token = the parent), which misses the
    // posix_spawn case where the child is hardened: the parent is NOT
    // hardened (it's the process that issued posix_spawn, ergo loaded the
    // dylib), so the exec-time arming never sees a hardened bit.
    //
    // Arming on the child after fork closes the TREE-04 transitive
    // coverage gap: if the hardened child fails to inject the dylib (DYLD
    // env stripped), no DylibLoaded arrives within the gap window and the
    // detector records `ConfirmedHardened` and fail-closes the child rather
    // than letting it continue outside Stentorian Guard enforcement.
    if recorded_ok {
        let child_pid = ev.child_pid as libc::pid_t;
        if is_hardened_runtime(child_pid) {
            let gap = CoverageGap::ConfirmedHardened {
                binary_path: String::new(), // filled by ExecEvent if/when it arrives
                detected_at_ms: unix_ms_now(),
            };
            // v0.3: pass forensic sinks so the gap fire also
            // updates recent_gaps + log_writer.
            state.gap_detector.arm_enforced_with_forensics(
                child,
                gap,
                state.process_tree.clone(),
                Some(state.recent_gaps.clone()),
                Some(state.log_writer.clone()),
            );
        }
    }
    if let Err(e) = write_tagged(stream, MessageTag::ForkEvent, &reply) {
        error!(error = %e, "failed to send ForkAck");
    }
}

fn handle_exec_event(stream: &mut UnixStream, peer_token: AuditToken, state: &Arc<DaemonState>) {
    let ev: ExecEvent = match read_tagged_body(stream, MessageTag::ExecEvent) {
        Ok(m) => m,
        Err(e) => {
            warn!(error = %e, "exec event decode failed");
            let _ = write_tagged(
                stream,
                MessageTag::ExecEvent,
                &ExecAck::err(format!("decode: {e}")),
            );
            return;
        }
    };
    // v0.3: accept V2 (pm_env defaults to empty via #[serde(default)])
    // and V3 (carries pm_env). Reject anything else.
    if !matches!(ev.schema_version, IPC_SCHEMA_V2 | IPC_SCHEMA_V3) {
        let _ = write_tagged(
            stream,
            MessageTag::ExecEvent,
            &ExecAck::err(format!(
                "schema_version {} not in [IPC_SCHEMA_V2, IPC_SCHEMA_V3]",
                ev.schema_version
            )),
        );
        return;
    }
    // T-02-01-06: cap target_path length.
    if ev.target_path.len() > ExecEvent::MAX_TARGET_PATH {
        let _ = write_tagged(
            stream,
            MessageTag::ExecEvent,
            &ExecAck::err(format!(
                "target_path exceeds {} bytes",
                ExecEvent::MAX_TARGET_PATH
            )),
        );
        return;
    }
    // BLOCKER-02 fix: verify the peer is in the tracked tree BEFORE recording
    // an exec or arming the gap detector. An untracked peer (DYLD-injected
    // dylib in a process outside `stt-guard wrap`) must not be able to mutate
    // tree state or arm a coverage-gap timer.
    if !state.process_tree.is_tracked(&peer_token) {
        debug!(
            peer_pid = peer_token.val[5],
            "ExecEvent from untracked peer; ignoring (peer is not under stt-guard wrap)"
        );
        let _ = write_tagged(
            stream,
            MessageTag::ExecEvent,
            &ExecAck::err("untracked peer; ignoring exec event"),
        );
        return;
    }
    // The exec'ing process is the peer (peer_token); record_exec updates its binary_path.
    //
    // WARNING (v0.2 review): `from_utf8_lossy` silently replaces
    // invalid UTF-8 bytes with U+FFFD. Filesystem paths can technically
    // contain arbitrary bytes; a path with invalid UTF-8 will be mangled
    // in storage and incorrect in subsequent forensic logs. Storing the
    // raw `Vec<u8>` end-to-end is a wider refactor (touches `ProcessNode`,
    // `record_exec`, `CoverageGap`, gap_detector tests) and is documented
    // as deferred work in REVIEW-FIX.md. Until then, log at warn-level
    // when invalid UTF-8 is detected so the forensic loss is visible
    // rather than silent.
    if std::str::from_utf8(&ev.target_path).is_err() {
        warn!(
            peer_pid = peer_token.val[5],
            len = ev.target_path.len(),
            "WARNING-10: ExecEvent target_path contains non-UTF-8 bytes; \
             storing lossy form (forensic fidelity loss)"
        );
    }
    let target_path = String::from_utf8_lossy(&ev.target_path).into_owned();
    let _ = state
        .process_tree
        .record_exec(peer_token, target_path.clone());

    // v0.3: capture PM env subset onto ProcessNode for log enrichment.
    // extract_pm_env applies the prefix allowlist + secret denylist + wire-size cap.
    // V2 messages decode with pm_env=[] (via #[serde(default)]) → captured is empty → no-op.
    let captured = crate::env_capture::extract_pm_env(&ev.pm_env);
    // BLOCKER: emit a forensic tracing line so e2e
    // tests can drain_stderr() and HARD-assert that pm_env capture
    // landed without depending on JSONL log timing. Privacy-safe:
    // we log the COUNT of captured pairs and the COUNT of pairs the
    // dylib sent (some of which the daemon's denylist may have
    // additionally dropped), NEVER values. Emitted at info-level so
    // the default RUST_LOG=info captures it in the e2e harness.
    //
    // Uses the module-default target (`guard_daemon::ipc_server`) NOT a
    // custom target — RUST_LOG=info matches by module-prefix, and a custom
    // target like `stt-guard.exec.pm_env` would NOT match
    // `guard_daemon=info` (RUST_LOG matches against the event's target,
    // which defaults to the module path). Discovered the hard way during
    // the BLOCKER e2e wiring — see git log on this file.
    //
    // Emitted unconditionally (even when captured.is_empty()) so the test
    // can distinguish "ExecEvent never reached the handler" (no log line
    // at all) from "ExecEvent reached the handler but pm_env was empty"
    // (log line with captured=0, wire_pairs=0).
    info!(
        peer_pid = peer_token.val[5],
        captured = captured.len(),
        wire_pairs = ev.pm_env.len(),
        schema_version = ev.schema_version,
        "pm_env_captured"
    );
    if !captured.is_empty() {
        state
            .process_tree
            .set_pm_env_snapshot(&peer_token, captured);
    }

    // step A: csops pre-check on the calling process.
    let kernel_pid = libc::pid_t::try_from(peer_token.val[5]).unwrap_or(-1);
    if is_hardened_runtime(kernel_pid) {
        // Arm a 500 ms gap timer; cancelled by DylibLoaded if the new image
        // (post-exec) reports successful injection.
        let gap = CoverageGap::ConfirmedHardened {
            binary_path: target_path,
            detected_at_ms: unix_ms_now(),
        };
        // v0.3: pass forensic sinks so the gap fire also
        // updates recent_gaps + log_writer.
        state.gap_detector.arm_enforced_with_forensics(
            peer_token,
            gap,
            state.process_tree.clone(),
            Some(state.recent_gaps.clone()),
            Some(state.log_writer.clone()),
        );
    }
    if let Err(e) = write_tagged(stream, MessageTag::ExecEvent, &ExecAck::ok()) {
        error!(error = %e, "failed to send ExecAck");
    }
}

fn handle_dylib_loaded(stream: &mut UnixStream, peer_token: AuditToken, state: &Arc<DaemonState>) {
    let ev: DylibLoaded = match read_tagged_body(stream, MessageTag::DylibLoaded) {
        Ok(m) => m,
        Err(e) => {
            warn!(error = %e, "DylibLoaded decode failed");
            let _ = write_tagged(
                stream,
                MessageTag::DylibLoaded,
                &DylibLoadedAck::err(format!("decode: {e}")),
            );
            return;
        }
    };
    if ev.schema_version != IPC_SCHEMA_V2 {
        let _ = write_tagged(
            stream,
            MessageTag::DylibLoaded,
            &DylibLoadedAck::err(format!(
                "schema_version {} != IPC_SCHEMA_V2",
                ev.schema_version
            )),
        );
        return;
    }
    // BLOCKER-02 fix: only cancel a gap-detector timer for a tracked peer.
    // An untracked peer should not be able to silently cancel timers that
    // were never armed for it (no-op anyway), but rejecting cleanly avoids
    // the dylib re-trying.
    if !state.process_tree.is_tracked(&peer_token) {
        debug!(
            peer_pid = peer_token.val[5],
            "DylibLoaded from untracked peer; ignoring"
        );
        let _ = write_tagged(
            stream,
            MessageTag::DylibLoaded,
            &DylibLoadedAck::err("untracked peer; ignoring dylib_loaded event"),
        );
        return;
    }
    // Cancel any pending gap-detector timer for the peer's audit token.
    // Note: the dylib reports DylibLoaded with the audit_token of the NEW
    // process image (post-exec), but the peer-auth gives us the same token
    // (the connecting process is the new image). Cancel under peer_token.
    let cancelled = state.gap_detector.cancel(&peer_token);
    debug!(pid = peer_token.val[5], cancelled, "DylibLoaded received");
    if let Err(e) = write_tagged(stream, MessageTag::DylibLoaded, &DylibLoadedAck::ok()) {
        error!(error = %e, "failed to send DylibLoadedAck");
    }
}

fn unix_ms_now() -> u64 {
    let millis = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis();
    u64::try_from(millis).unwrap_or(u64::MAX)
}

fn handle_prepare_snapshot_frame(
    stream: &mut UnixStream,
    _peer_token: AuditToken,
    state: &Arc<DaemonState>,
) {
    let req: PrepareSnapshot = match read_tagged_body(stream, MessageTag::PrepareSnapshot) {
        Ok(m) => m,
        Err(e) => {
            warn!(error = %e, "PrepareSnapshot decode failed");
            let _ = write_tagged(
                stream,
                MessageTag::PrepareSnapshot,
                &SnapshotReply::err(format!("decode: {e}")),
            );
            return;
        }
    };
    // v0.3: accept V2 OR V3. V3 carries is_tty + baseline_mode
    // (#[serde(default)] on those fields → false on V2 decode, so no branch needed).
    if !matches!(req.schema_version, IPC_SCHEMA_V2 | IPC_SCHEMA_V3) {
        let _ = write_tagged(
            stream,
            MessageTag::PrepareSnapshot,
            &SnapshotReply::err(format!(
                "schema_version {} not in [IPC_SCHEMA_V2, IPC_SCHEMA_V3]",
                req.schema_version
            )),
        );
        return;
    }
    let cwd = std::path::PathBuf::from(req.cwd);
    let reply = crate::handlers::prepare_snapshot::handle_prepare_snapshot_v4_full(
        state,
        &cwd,
        req.is_tty,
        req.baseline_mode,
    );
    if let Err(e) = write_tagged(stream, MessageTag::PrepareSnapshot, &reply) {
        error!(error = %e, "failed to send SnapshotReply");
    }
}

fn handle_prepare_snapshot_inputs_frame(stream: &mut UnixStream, state: &Arc<DaemonState>) {
    let req: PrepareSnapshot = match read_tagged_body(stream, MessageTag::PrepareSnapshotInputs) {
        Ok(m) => m,
        Err(e) => {
            warn!(error = %e, "PrepareSnapshotInputs decode failed");
            let _ = write_tagged(
                stream,
                MessageTag::PrepareSnapshotInputs,
                &SnapshotInputsReply::err(format!("decode: {e}")),
            );
            return;
        }
    };
    if !matches!(
        req.schema_version,
        IPC_SCHEMA_V2 | IPC_SCHEMA_V3 | IPC_SCHEMA_V5
    ) {
        let _ = write_tagged(
            stream,
            MessageTag::PrepareSnapshotInputs,
            &SnapshotInputsReply::err(format!(
                "schema_version {} not in [IPC_SCHEMA_V2, IPC_SCHEMA_V3, IPC_SCHEMA_V5]",
                req.schema_version
            )),
        );
        return;
    }
    let cwd = std::path::PathBuf::from(req.cwd);
    let reply = crate::handlers::prepare_snapshot::handle_prepare_snapshot_inputs_full(
        state,
        &cwd,
        req.is_tty,
        req.baseline_mode,
    );
    if let Err(e) = write_tagged(stream, MessageTag::PrepareSnapshotInputs, &reply) {
        error!(error = %e, "failed to send SnapshotInputsReply");
    }
}

fn handle_publish_signed_snapshot_frame(stream: &mut UnixStream, state: &Arc<DaemonState>) {
    let req: PublishSignedSnapshot =
        match read_tagged_body(stream, MessageTag::PublishSignedSnapshot) {
            Ok(m) => m,
            Err(e) => {
                warn!(error = %e, "PublishSignedSnapshot decode failed");
                let _ = write_tagged(
                    stream,
                    MessageTag::PublishSignedSnapshot,
                    &SnapshotReply::err(format!("decode: {e}")),
                );
                return;
            }
        };
    let reply = crate::handlers::prepare_snapshot::handle_publish_signed_snapshot_full(state, req);
    if let Err(e) = write_tagged(stream, MessageTag::PublishSignedSnapshot, &reply) {
        error!(error = %e, "failed to send PublishSignedSnapshot reply");
    }
}

fn handle_resolve_frame(stream: &mut UnixStream, peer_token: AuditToken, state: &Arc<DaemonState>) {
    let req: Resolve = match read_tagged_body(stream, MessageTag::Resolve) {
        Ok(m) => m,
        Err(e) => {
            warn!(error = %e, "Resolve decode failed");
            let _ = write_tagged(
                stream,
                MessageTag::Resolve,
                &ResolveReply::err(format!("decode: {e}")),
            );
            return;
        }
    };
    if req.schema_version != IPC_SCHEMA_V2 {
        let _ = write_tagged(
            stream,
            MessageTag::Resolve,
            &ResolveReply::err(format!(
                "schema_version {} != IPC_SCHEMA_V2",
                req.schema_version
            )),
        );
        return;
    }

    if try_handle_prompted_resolve(stream, peer_token, state, &req) {
        return;
    }

    if let Some(policy_deny) = resolve_policy_deny(state, peer_token, &req) {
        write_resolve_policy_deny(stream, state, &req, policy_deny);
        return;
    }

    // Default path: perform DNS resolution and return.
    let reply = crate::handlers::resolve::handle_resolve(&req.host, req.port);
    if let Err(e) = write_tagged(stream, MessageTag::Resolve, &reply) {
        error!(error = %e, "failed to send ResolveReply");
    }
}

struct ResolvePolicyDeny {
    run_uuid: String,
    source: guard_core::SourceKind,
    entries: Vec<guard_core::AllowlistEntry>,
}

fn try_handle_prompted_resolve(
    stream: &mut UnixStream,
    peer_token: AuditToken,
    state: &Arc<DaemonState>,
    req: &Resolve,
) -> bool {
    let Some((run_uuid, is_baseline)) = prompt_eligible_run(state, &peer_token) else {
        return false;
    };

    let loaded = state
        .process_tree
        .get_run(&run_uuid)
        .and_then(|run| crate::handlers::resolve::load_run_entries(&run.snapshot_path));
    let (policy_verdict, policy_source) = loaded.as_ref().map_or(
        (
            guard_core::Verdict::Deny,
            guard_core::SourceKind::DefaultDeny,
        ),
        |entries| guard_core::policy::evaluate_policy(req.host.as_bytes(), None, false, entries),
    );

    if matches!(policy_verdict, guard_core::Verdict::Allow) {
        write_resolve_reply(stream, req, "policy-allowed fast path");
        return true;
    }

    if prompt_policy_blocks_without_prompt(
        stream,
        state,
        req,
        &run_uuid,
        policy_source,
        loaded.as_deref(),
    ) {
        return true;
    }

    if is_baseline && !matches!(policy_source, guard_core::SourceKind::SuspectDeny) {
        state.baseline_staging.record_allow(
            &run_uuid,
            "exact",
            &req.host,
            "learn: recorded by stt-guard wrap --learn",
        );
        write_resolve_reply(stream, req, "learn-mode allow");
        return true;
    }

    send_prompted_resolve(
        stream,
        peer_token,
        state,
        req,
        &run_uuid,
        policy_source,
        loaded.as_deref(),
    );
    true
}

fn prompt_eligible_run(
    state: &Arc<DaemonState>,
    peer_token: &AuditToken,
) -> Option<(String, bool)> {
    let node = state.process_tree.get_node(peer_token);
    let run = node
        .as_ref()
        .and_then(|node| state.process_tree.get_run(&node.run_uuid))?;
    if run.is_tty
        && state
            .process_tree
            .get_prompt_channel(&run.run_uuid)
            .is_some()
    {
        Some((run.run_uuid, run.baseline_mode))
    } else {
        None
    }
}

fn prompt_policy_blocks_without_prompt(
    stream: &mut UnixStream,
    state: &Arc<DaemonState>,
    req: &Resolve,
    run_uuid: &str,
    policy_source: guard_core::SourceKind,
    loaded: Option<&[guard_core::AllowlistEntry]>,
) -> bool {
    if !matches!(
        policy_source,
        guard_core::SourceKind::ConfirmedDeny | guard_core::SourceKind::BuiltinDeny
    ) {
        return false;
    }

    if matches!(policy_source, guard_core::SourceKind::ConfirmedDeny) {
        let was_approved =
            loaded.is_some_and(|entries| guard_core::has_user_allow(req.host.as_bytes(), entries));
        if was_approved {
            info!(
                host = %req.host,
                "confirmed-deny overrides user-allow — previously approved host now suspended"
            );
        }
    }

    let entries = loaded.unwrap_or(&[]);
    write_resolve_policy_deny(
        stream,
        state,
        req,
        ResolvePolicyDeny {
            run_uuid: run_uuid.to_string(),
            source: policy_source,
            entries: entries.to_vec(),
        },
    );
    true
}

fn send_prompted_resolve(
    stream: &mut UnixStream,
    peer_token: AuditToken,
    state: &Arc<DaemonState>,
    req: &Resolve,
    run_uuid: &str,
    policy_source: guard_core::SourceKind,
    loaded: Option<&[guard_core::AllowlistEntry]>,
) {
    let prompt_id = state.deferred_resolve.next_prompt_id();
    let outcome = state
        .prompt_dedup
        .coalesce(run_uuid, &req.host, req.port, &prompt_id);
    let effective_id = match outcome {
        crate::prompt::CoalesceOutcome::Fresh => prompt_id,
        crate::prompt::CoalesceOutcome::Existing(other_id) => other_id,
    };
    let package_context = crate::log_writer::package_context::infer_package_context_with_retry(
        &state.process_tree,
        &peer_token,
        "",
        std::time::Duration::from_millis(250),
    );
    let (tx, rx) = crossbeam_channel::bounded::<guard_core::Verdict>(1);
    state.deferred_resolve.insert(
        effective_id.clone(),
        DeferredEntry {
            run_uuid: run_uuid.to_string(),
            host: req.host.clone(),
            port: req.port,
            sender: tx,
            package_context: package_context.clone(),
        },
    );

    let request = resolve_prompt_request(
        state,
        &peer_token,
        req,
        &effective_id,
        policy_source,
        package_context,
        loaded.unwrap_or(&[]),
    );
    let Some(channel) = state.process_tree.get_prompt_channel(run_uuid) else {
        let _ = state.deferred_resolve.take(&effective_id);
        return;
    };
    if channel.try_send(request).is_err() {
        let _ = state.deferred_resolve.take(&effective_id);
        write_resolve_reply(stream, req, "channel-saturated fallback");
        return;
    }

    let verdict = rx
        .recv_timeout(std::time::Duration::from_secs(35))
        .unwrap_or_else(|_| {
            warn!(
                prompt_id = %effective_id,
                host = %req.host,
                "prompt timed out after 35s — denying and reclaiming worker"
            );
            let _ = state.deferred_resolve.take(&effective_id);
            state.prompt_dedup.forget(run_uuid, &req.host, req.port);
            guard_core::Verdict::Deny
        });
    write_prompt_verdict_resolve_reply(stream, req, verdict);
}

fn resolve_prompt_request(
    state: &Arc<DaemonState>,
    peer_token: &AuditToken,
    req: &Resolve,
    prompt_id: &str,
    policy_source: guard_core::SourceKind,
    package_context: Option<guard_ipc::PackageContext>,
    entries: &[guard_core::AllowlistEntry],
) -> guard_ipc::PromptRequest {
    let intel = crate::log_writer::enrich_from_entries(req.host.as_bytes(), entries);
    guard_ipc::PromptRequest {
        schema_version: IPC_SCHEMA_V3,
        prompt_id: prompt_id.to_string(),
        dest_host: req.host.clone(),
        dest_port: req.port,
        dest_ip: None,
        source_kind: policy_source.as_label().to_string(),
        source_locator: None,
        package_context,
        process: guard_ipc::ProcessCtx {
            pid: peer_token.val[5],
            pidversion: peer_token.val[7],
            argv0: state
                .process_tree
                .get_node(peer_token)
                .map(|node| node.binary_path)
                .unwrap_or_default(),
            cwd: String::new(),
        },
        intel: if intel.is_empty() { None } else { Some(intel) },
        suggested_rules: crate::prompt::generate_suggested_rules(&req.host),
    }
}

fn write_prompt_verdict_resolve_reply(
    stream: &mut UnixStream,
    req: &Resolve,
    verdict: guard_core::Verdict,
) {
    match verdict {
        guard_core::Verdict::Allow => write_resolve_reply(stream, req, "prompt allow"),
        guard_core::Verdict::Deny => {
            let _ = write_tagged(
                stream,
                MessageTag::Resolve,
                &ResolveReply::err(format!("connection to {} denied by user", req.host)),
            );
        }
    }
}

fn resolve_policy_deny(
    state: &Arc<DaemonState>,
    peer_token: AuditToken,
    req: &Resolve,
) -> Option<ResolvePolicyDeny> {
    let node = state.process_tree.get_node(&peer_token);
    let run = node
        .as_ref()
        .and_then(|node| state.process_tree.get_run(&node.run_uuid))?;
    let Some(entries) = crate::handlers::resolve::load_run_entries(&run.snapshot_path) else {
        warn!(
            snapshot_path = %run.snapshot_path.display(),
            "snapshot unreadable — denying resolve (fail-closed)"
        );
        return Some(ResolvePolicyDeny {
            run_uuid: run.run_uuid,
            source: guard_core::SourceKind::HardRule("fail-closed"),
            entries: vec![],
        });
    };

    let (verdict, source) =
        guard_core::policy::evaluate_policy(req.host.as_bytes(), None, false, &entries);
    if matches!(verdict, guard_core::Verdict::Allow) {
        return None;
    }
    if run.baseline_mode && !is_hard_resolve_deny(source) {
        state.baseline_staging.record_allow(
            &run.run_uuid,
            "exact",
            &req.host,
            "learn: recorded by stt-guard wrap --learn",
        );
        return None;
    }

    debug!(
        host = %req.host,
        source = ?source,
        "Resolve denied by policy gate"
    );
    Some(ResolvePolicyDeny {
        run_uuid: run.run_uuid,
        source,
        entries,
    })
}

fn is_hard_resolve_deny(source: guard_core::SourceKind) -> bool {
    matches!(
        source,
        guard_core::SourceKind::ConfirmedDeny
            | guard_core::SourceKind::BuiltinDeny
            | guard_core::SourceKind::HardRule(_)
    )
}

fn write_resolve_policy_deny(
    stream: &mut UnixStream,
    state: &Arc<DaemonState>,
    req: &Resolve,
    policy_deny: ResolvePolicyDeny,
) {
    use crate::log_writer::jsonl_row::{
        Decision, JSONL_SCHEMA_VERSION, LogRow, ProcessCtxLog, RootCtxLog, now_rfc3339,
    };

    let source_kind = policy_deny.source.as_label();
    let intel = crate::log_writer::enrich_from_entries(req.host.as_bytes(), &policy_deny.entries);
    let decision = Decision {
        schema_version: JSONL_SCHEMA_VERSION,
        ts: now_rfc3339(),
        verdict: "Deny",
        dest_host: req.host.clone(),
        dest_port: req.port,
        dest_ip: None,
        run_uuid: policy_deny.run_uuid,
        source_kind: source_kind.to_string(),
        source_locator: None,
        process: ProcessCtxLog {
            pid: 0,
            pidversion: 0,
            argv: vec![],
            cwd: String::new(),
        },
        parent: ProcessCtxLog {
            pid: 0,
            pidversion: 0,
            argv: vec![],
            cwd: String::new(),
        },
        root: RootCtxLog {
            audit_token: [0; 8],
            argv: vec![],
        },
        package_context: None,
        intel: if intel.is_empty() { None } else { Some(intel) },
    };
    state.log_writer.send(LogRow::Block(decision));

    let _ = write_tagged(
        stream,
        MessageTag::Resolve,
        &ResolveReply::err(format!("denied by policy: {source_kind}")),
    );
}

fn write_resolve_reply(stream: &mut UnixStream, req: &Resolve, context: &str) {
    let reply = crate::handlers::resolve::handle_resolve(&req.host, req.port);
    if let Err(e) = write_tagged(stream, MessageTag::Resolve, &reply) {
        error!(error = %e, "failed to send ResolveReply ({context})");
    }
}

fn handle_env_not_propagated_frame(
    stream: &mut UnixStream,
    peer_token: AuditToken,
    state: &Arc<DaemonState>,
) {
    let req: EnvNotPropagatedGap = match read_tagged_body(stream, MessageTag::EnvNotPropagatedGap) {
        Ok(m) => m,
        Err(e) => {
            warn!(error = %e, "EnvNotPropagatedGap decode failed");
            let _ = write_tagged(
                stream,
                MessageTag::EnvNotPropagatedGap,
                &EnvNotPropagatedGapAck::err(format!("decode: {e}")),
            );
            return;
        }
    };
    if req.schema_version != IPC_SCHEMA_V2 {
        let _ = write_tagged(
            stream,
            MessageTag::EnvNotPropagatedGap,
            &EnvNotPropagatedGapAck::err(format!(
                "schema_version {} != IPC_SCHEMA_V2",
                req.schema_version
            )),
        );
        return;
    }
    // BLOCKER-02 mirror: untracked peer → diagnostic reply, no gap recorded.
    if !state.process_tree.is_tracked(&peer_token) {
        debug!(
            peer_pid = peer_token.val[5],
            "EnvNotPropagatedGap from untracked peer; ignoring (peer is not under stt-guard wrap)"
        );
        let _ = write_tagged(
            stream,
            MessageTag::EnvNotPropagatedGap,
            &EnvNotPropagatedGapAck::err("untracked peer; ignoring env-not-propagated gap"),
        );
        return;
    }
    // The gap is recorded on the PEER (the process that called posix_spawn with
    // the cleared envp). We use `peer_token` (kernel-sourced, already verified
    // to be in the tree by the is_tracked gate above) rather than the
    // wire-claimed `parent_audit_token` (which is advisory only — it may not
    // exactly match the full 8-field kernel token stored in the tree).
    //
    // The wire's `parent_audit_token` still carries useful advisory context
    // (e.g. BLOCKER-07 ppid hint) that future forensic tools can use.
    let binary_path = String::from_utf8_lossy(&req.child_binary_path).into_owned();
    let gap = CoverageGap::EnvNotPropagated {
        binary_path: binary_path.clone(),
        detected_at_ms: req.detected_at_ms,
    };
    match state.process_tree.set_coverage_gap(peer_token, gap) {
        Ok(()) => {
            // The literal substrings `TREE-06` and `env-not-propagated`
            // are the e2e test's grep targets in env_not_propagated.rs
            // (Task 3). Both must remain in this message verbatim.
            warn!(
                target: "stt-guard.tree06",
                peer_pid = peer_token.val[5],
                binary_path = %binary_path,
                detected_at_ms = req.detected_at_ms,
                "TREE-06 env-not-propagated gap recorded"
            );

            // v0.3: also publish to recent_gaps + log_writer.
            // Use the run_uuid from the node for forensic correlation.
            let run_uuid = state
                .process_tree
                .get_node(&peer_token)
                .map(|n| n.run_uuid.clone())
                .unwrap_or_default();
            let binary_path_opt = if binary_path.is_empty() {
                None
            } else {
                Some(binary_path.clone())
            };
            let gap_info = guard_ipc::GapInfo {
                run_uuid: run_uuid.clone(),
                gap_kind: "env-not-propagated".to_string(),
                binary_path: binary_path_opt.clone(),
                detected_at_ms: req.detected_at_ms,
            };
            state.recent_gaps.push(gap_info);
            state.log_writer.send(crate::log_writer::LogRow::Gap(
                crate::log_writer::GapRecord {
                    schema_version: crate::log_writer::JSONL_SCHEMA_VERSION,
                    ts: crate::log_writer::now_rfc3339(),
                    run_uuid,
                    gap_kind: "env-not-propagated",
                    process: crate::log_writer::ProcessCtxLog {
                        pid: peer_token.val[5],
                        pidversion: peer_token.val[7],
                        argv: vec![],
                        cwd: String::new(),
                    },
                    binary_path: binary_path_opt,
                },
            ));
        }
        Err(e) => {
            // Should not happen — peer_token is in the tree (is_tracked passed).
            warn!(error = ?e, "EnvNotPropagatedGap: set_coverage_gap failed (unexpected)");
        }
    }
    if let Err(e) = write_tagged(
        stream,
        MessageTag::EnvNotPropagatedGap,
        &EnvNotPropagatedGapAck::ok(),
    ) {
        error!(error = %e, "failed to send EnvNotPropagatedGapAck");
    }
}
