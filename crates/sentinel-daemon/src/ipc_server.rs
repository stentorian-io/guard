//! Sync UnixListener accept loop with bounded thread pool dispatch.
//!
//! Phase 2 D-33: synchronous fork/exec IPC volume requires real concurrency.
//! 16 worker threads consume from a bounded channel; accept never blocks on
//! a worker. Under sustained flood the channel fills, accept's try_send
//! returns Err, the new connection is dropped, the dylib's IPC times out
//! at 250ms, and the dylib fails-closed at fork — the safe outcome.
//!
//! Backward compat: Phase 1 RegisterRoot frames (length-prefixed CBOR) are
//! detected by classify_frame and dispatched to the legacy register handler.
//! The Phase 1 contract is preserved — see plan 02-01 for the FROZEN status.
//!
//! BENIGN-EOF CONTRACT (T-01-05-09): plan 08's `probe_daemon_alive` is a
//! connect-only liveness probe — it opens a stream and drops it immediately,
//! sending no frame. From this side, classify_frame returns
//! `DispatchError::Io(e)` where `e.kind() == ErrorKind::UnexpectedEof`. We
//! recognize that case as a benign liveness probe: log at debug, mutate no
//! state, write no Reply, close.

use crate::gap_detector::GapDetector;
use crate::ipc_dispatch::{classify_frame, DispatchError, FrameKind, MessageTag};
use crate::os_ffi::is_hardened_runtime;
use crate::peer_auth::authenticate;
use crate::tracked::{CoverageGap, ProcessTree};
use crossbeam_channel::{bounded, TrySendError};
use sentinel_core::AuditToken;
use sentinel_ipc::frame::{read_frame, write_frame};
use sentinel_ipc::{
    DylibLoaded, DylibLoadedAck, ExecAck, ExecEvent, ForkAck, ForkEvent, IPC_SCHEMA_V2, IpcError,
    PrepareSnapshot, RegisterRoot, Reply, Resolve, ResolveReply, SnapshotReply, TrustPolicy,
    TrustPolicyReply,
};
use std::io::{ErrorKind, Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
use std::sync::Arc;
use std::time::SystemTime;
use tracing::{debug, error, info, warn};

pub const WORKER_THREADS: usize = 16;
pub const ACCEPT_QUEUE_DEPTH: usize = 64;

/// Shared daemon state passed to every worker handler.
pub struct DaemonState {
    pub process_tree: Arc<ProcessTree>,
    pub gap_detector: Arc<GapDetector>,
    pub rule_store: Arc<crate::rule_store::RuleStore>,
    pub curated: Arc<Vec<sentinel_core::AllowlistEntry>>,
    pub state_dir: std::path::PathBuf,
}

impl DaemonState {
    pub fn new(
        process_tree: Arc<ProcessTree>,
        gap_detector: Arc<GapDetector>,
        rule_store: Arc<crate::rule_store::RuleStore>,
        curated: Arc<Vec<sentinel_core::AllowlistEntry>>,
        state_dir: std::path::PathBuf,
    ) -> Self {
        Self {
            process_tree,
            gap_detector,
            rule_store,
            curated,
            state_dir,
        }
    }
}

pub struct IpcServer {
    listener: UnixListener,
    state: Arc<DaemonState>,
}

impl IpcServer {
    /// Bind a fresh listener at `socket_path`. Removes any stale socket file
    /// and sets mode 0600 on the new socket (so only the user can connect).
    pub fn bind(socket_path: &Path, state: Arc<DaemonState>) -> std::io::Result<Self> {
        let _ = std::fs::remove_file(socket_path);
        let listener = UnixListener::bind(socket_path)?;
        let mut perms = std::fs::metadata(socket_path)?.permissions();
        perms.set_mode(0o600);
        std::fs::set_permissions(socket_path, perms)?;
        Ok(Self { listener, state })
    }

    /// Single-shot accept — used by integration tests.
    pub fn accept_one(&self) -> std::io::Result<()> {
        let (stream, _) = self.listener.accept()?;
        Self::handle(stream, &self.state);
        Ok(())
    }

    /// Run forever — bounded thread pool consumes from a bounded channel.
    /// Takes self by value because the listener and channel senders move into
    /// long-lived workers.
    pub fn run_forever(self) -> std::io::Result<()> {
        let (tx, rx) = bounded::<UnixStream>(ACCEPT_QUEUE_DEPTH);
        for _ in 0..WORKER_THREADS {
            let rx = rx.clone();
            let state = self.state.clone();
            std::thread::spawn(move || {
                while let Ok(stream) = rx.recv() {
                    Self::handle(stream, &state);
                }
            });
        }
        loop {
            let (stream, _) = self.listener.accept()?;
            // Backpressure: try_send drops the connection on a full queue.
            // The dylib's IPC times out → fork fails-closed (D-33).
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

    fn handle(mut stream: UnixStream, state: &Arc<DaemonState>) {
        let peer_id = match authenticate(&stream) {
            Ok(id) => id,
            Err(e) => {
                warn!(error = %e, "peer auth failed");
                let _ = write_legacy_err(&mut stream, format!("peer auth: {e}"));
                return;
            }
        };
        let peer_token = match peer_id.as_policy_key() {
            Some(k) => *k,
            None => {
                warn!("peer authenticated as Unverified — refusing");
                let _ = write_legacy_err(&mut stream, "peer not Verified");
                return;
            }
        };

        // Classify the frame: tagged or legacy length-prefixed.
        let kind = match classify_frame(&mut stream) {
            Ok(k) => k,
            Err(DispatchError::Io(e)) if e.kind() == ErrorKind::UnexpectedEof => {
                // Connect-only liveness probe (Phase 1 plan 08 semantics) —
                // benign; no state change, no Reply written.
                debug!(
                    peer_pid = peer_token.val[5],
                    "benign liveness probe (connect+EOF)"
                );
                return;
            }
            Err(e) => {
                warn!(error = %e, "classify_frame failed");
                let _ = write_legacy_err(&mut stream, format!("classify: {e}"));
                return;
            }
        };

        match kind {
            FrameKind::LegacyUntagged { first_length_byte } => {
                handle_legacy_register_root(&mut stream, first_length_byte, peer_token, state);
            }
            FrameKind::Tagged(MessageTag::ForkEvent) => {
                handle_fork_event(&mut stream, peer_token, state);
            }
            FrameKind::Tagged(MessageTag::ExecEvent) => {
                handle_exec_event(&mut stream, peer_token, state);
            }
            FrameKind::Tagged(MessageTag::DylibLoaded) => {
                handle_dylib_loaded(&mut stream, peer_token, state);
            }
            FrameKind::Tagged(MessageTag::PrepareSnapshot) => {
                handle_prepare_snapshot_frame(&mut stream, peer_token, state);
            }
            FrameKind::Tagged(MessageTag::TrustPolicy) => {
                handle_trust_policy_frame(&mut stream, peer_token, state);
            }
            FrameKind::Tagged(MessageTag::Resolve) => {
                handle_resolve_frame(&mut stream, peer_token, state);
            }
        }
    }
}

/// Write a Phase 1 Reply::Err frame as a fallback for diagnostic responses
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
    // Bound check: MAX_FRAME_BYTES (64 KiB) per sentinel-ipc::frame.
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
    // ENF-08: trust kernel-sourced peer token, NOT wire-claimed token.
    let wire_pid = msg.audit_token.val[5];
    let kernel_pid = peer_token.val[5];
    if wire_pid != kernel_pid {
        warn!(
            wire_pid,
            kernel_pid, "wire-claimed audit token disagrees with kernel-sourced; trusting kernel"
        );
    }
    // Phase 2: insert_root replaces TrackedRoots::insert. We don't have a
    // run_uuid yet (PrepareSnapshot is plan 02-06); use a placeholder that
    // plan 02-06's PrepareSnapshot handler can later upgrade to a real uuid.
    let inserted = state
        .process_tree
        .insert_root(peer_token, String::new(), String::new());
    info!(
        pid = kernel_pid,
        pidversion = peer_token.val[7],
        inserted,
        "registered tracked root"
    );
    if let Err(e) = write_frame(stream, &Reply::ack()) {
        error!(error = %e, "failed to send Ack");
    }
}

fn read_tagged_body<T>(stream: &mut UnixStream) -> Result<T, IpcError>
where
    T: serde::de::DeserializeOwned,
{
    read_frame(stream)
}

fn write_tagged<T>(stream: &mut UnixStream, tag: MessageTag, msg: &T) -> Result<(), IpcError>
where
    T: serde::Serialize,
{
    // Tag byte first, then length-prefixed CBOR body — symmetric with classify_frame.
    if let Err(e) = stream.write_all(&[tag.as_byte()]) {
        return Err(IpcError::Io(e));
    }
    write_frame(stream, msg)
}

fn handle_fork_event(stream: &mut UnixStream, peer_token: AuditToken, state: &Arc<DaemonState>) {
    let ev: ForkEvent = match read_tagged_body(stream) {
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
    // ENF-08: trust peer-auth, not wire-claimed parent.
    let wire_parent_pid = ev.parent_audit_token.val[5];
    let kernel_pid = peer_token.val[5];
    if wire_parent_pid != kernel_pid {
        warn!(
            wire_parent_pid, kernel_pid,
            "ForkEvent wire-claimed parent disagrees with peer-auth; trusting peer-auth"
        );
    }
    // Construct child audit token from wire pid + pidversion.
    // The kernel-sourced peer token tells us the parent; the wire tells us the
    // child's identity (which must be obtained by the dylib via proc_pidinfo
    // before sending — see plan 02-05).
    let child = AuditToken {
        val: [
            0,
            0,
            0,
            0,
            0,
            ev.child_pid as u32,
            0,
            ev.child_pidversion,
        ],
    };
    let result = state.process_tree.record_fork(peer_token, child);
    let reply = match result {
        Ok(()) => ForkAck::ok(),
        Err(e) => ForkAck::err(format!("record_fork: {e}")),
    };
    if let Err(e) = write_tagged(stream, MessageTag::ForkEvent, &reply) {
        error!(error = %e, "failed to send ForkAck");
    }
}

fn handle_exec_event(stream: &mut UnixStream, peer_token: AuditToken, state: &Arc<DaemonState>) {
    let ev: ExecEvent = match read_tagged_body(stream) {
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
    if ev.schema_version != IPC_SCHEMA_V2 {
        let _ = write_tagged(
            stream,
            MessageTag::ExecEvent,
            &ExecAck::err(format!(
                "schema_version {} != IPC_SCHEMA_V2",
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
    // The exec'ing process is the peer (peer_token); record_exec updates its binary_path.
    let target_path = String::from_utf8_lossy(&ev.target_path).into_owned();
    let _ = state
        .process_tree
        .record_exec(peer_token, target_path.clone());

    // D-34 Phase A: csops pre-check on the calling process.
    let kernel_pid = peer_token.val[5] as libc::pid_t;
    if is_hardened_runtime(kernel_pid) {
        // Arm a 500 ms gap timer; cancelled by DylibLoaded if the new image
        // (post-exec) reports successful injection.
        let gap = CoverageGap::ConfirmedHardened {
            binary_path: target_path,
            detected_at_ms: unix_ms_now(),
        };
        state
            .gap_detector
            .arm(peer_token, gap, state.process_tree.clone());
    }
    if let Err(e) = write_tagged(stream, MessageTag::ExecEvent, &ExecAck::ok()) {
        error!(error = %e, "failed to send ExecAck");
    }
}

fn handle_dylib_loaded(stream: &mut UnixStream, peer_token: AuditToken, state: &Arc<DaemonState>) {
    let ev: DylibLoaded = match read_tagged_body(stream) {
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
    // Cancel any pending gap-detector timer for the peer's audit token.
    // Note: the dylib reports DylibLoaded with the audit_token of the NEW
    // process image (post-exec), but the peer-auth gives us the same token
    // (the connecting process is the new image). Cancel under peer_token.
    let cancelled = state.gap_detector.cancel(&peer_token);
    debug!(
        pid = peer_token.val[5],
        cancelled, "DylibLoaded received"
    );
    if let Err(e) = write_tagged(stream, MessageTag::DylibLoaded, &DylibLoadedAck::ok()) {
        error!(error = %e, "failed to send DylibLoadedAck");
    }
}

fn unix_ms_now() -> u64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

fn handle_prepare_snapshot_frame(
    stream: &mut UnixStream,
    _peer_token: AuditToken,
    state: &Arc<DaemonState>,
) {
    let req: PrepareSnapshot = match read_tagged_body(stream) {
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
    if req.schema_version != IPC_SCHEMA_V2 {
        let _ = write_tagged(
            stream,
            MessageTag::PrepareSnapshot,
            &SnapshotReply::err(format!(
                "schema_version {} != IPC_SCHEMA_V2",
                req.schema_version
            )),
        );
        return;
    }
    let cwd = std::path::PathBuf::from(req.cwd);
    let reply = crate::handlers::prepare_snapshot::handle_prepare_snapshot(
        &cwd,
        &state.curated,
        &state.rule_store,
        &state.process_tree,
        &state.state_dir,
    );
    if let Err(e) = write_tagged(stream, MessageTag::PrepareSnapshot, &reply) {
        error!(error = %e, "failed to send SnapshotReply");
    }
}

fn handle_trust_policy_frame(
    stream: &mut UnixStream,
    _peer_token: AuditToken,
    state: &Arc<DaemonState>,
) {
    let req: TrustPolicy = match read_tagged_body(stream) {
        Ok(m) => m,
        Err(e) => {
            warn!(error = %e, "TrustPolicy decode failed");
            let _ = write_tagged(
                stream,
                MessageTag::TrustPolicy,
                &TrustPolicyReply::err(format!("decode: {e}")),
            );
            return;
        }
    };
    if req.schema_version != IPC_SCHEMA_V2 {
        let _ = write_tagged(
            stream,
            MessageTag::TrustPolicy,
            &TrustPolicyReply::err(format!(
                "schema_version {} != IPC_SCHEMA_V2",
                req.schema_version
            )),
        );
        return;
    }
    let reply =
        crate::handlers::trust_policy::handle_trust_policy(&req.path, &req.sha256, &state.rule_store);
    if let Err(e) = write_tagged(stream, MessageTag::TrustPolicy, &reply) {
        error!(error = %e, "failed to send TrustPolicyReply");
    }
}

fn handle_resolve_frame(
    stream: &mut UnixStream,
    _peer_token: AuditToken,
    _state: &Arc<DaemonState>,
) {
    let req: Resolve = match read_tagged_body(stream) {
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
    let reply = crate::handlers::resolve::handle_resolve(&req.host, req.port);
    if let Err(e) = write_tagged(stream, MessageTag::Resolve, &reply) {
        error!(error = %e, "failed to send ResolveReply");
    }
}
