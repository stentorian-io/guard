//! Two-step coverage-gap detector.
//!
//! When the daemon receives an `ExecEvent` and the calling process's csops
//! flags indicate hardened-runtime, this module schedules a 500 ms timer
//! that watches for a matching `DylibLoaded` arrival. If none arrives, the
//! gap is recorded on the relevant node in the `ProcessTree`. Enforced arms
//! also kill the process so it cannot continue outside Stentorian Guard coverage.
//! If `DylibLoaded` arrives in time (cancel called), the gap is NOT recorded.
//!
//! Implementation: one `std::thread` per armed timer. Each thread sleeps up
//! to 500 ms or until a cancel signal arrives via crossbeam-channel.
//! Threads are short-lived (≤ 500 ms) so peak thread count is bounded
//! by `ExecEvent` rate × 500 ms.
//!
//! v0.3: on gap fire, ALSO push to `recent_gaps` ring and
//! emit a `LogRow::Gap` to `log_writer` (repudiation mitigation).

use crate::log_writer::{GapRecord, JSONL_SCHEMA_VERSION, LogRow, LogWriter, now_rfc3339};
use crate::prompt::RecentGapsRing;
use crate::tracked::{CoverageGap, ProcessTree};
use crossbeam_channel::{Sender, bounded};
use guard_core::AuditToken;
use guard_ipc::GapInfo;
use guard_os::errno::last_errno;
use guard_os::process::kernel_pidversion;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tracing::{debug, warn};

pub const GAP_TIMEOUT_MS: u64 = 500;

#[derive(Default)]
pub struct GapDetector {
    pending: Mutex<HashMap<AuditToken, Sender<()>>>,
}

#[derive(Clone, Copy)]
enum TimeoutAction {
    RecordOnly,
    KillProcess,
}

impl GapDetector {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Arm a timeout. If `cancel(audit_token)` is not called within
    /// `GAP_TIMEOUT_MS`, sets `pending_gap` on the node in `tree`.
    /// Re-arming the same token cancels the prior timer.
    ///
    /// v0.3: on timeout, ALSO push to `recent_gaps` + `log_writer`
    /// (two independent forensic records of every gap).
    pub fn arm(&self, audit_token: AuditToken, pending_gap: CoverageGap, tree: Arc<ProcessTree>) {
        self.arm_with_forensics(audit_token, pending_gap, tree, None, None);
    }

    /// Extended arm that also records the gap in `recent_gaps` and `log_writer`
    /// when provided. Called from `ipc_server.rs` after v0.3 wires
    /// the forensic sinks into the `ExecEvent` / `ForkEvent` handlers.
    pub fn arm_with_forensics(
        &self,
        audit_token: AuditToken,
        pending_gap: CoverageGap,
        tree: Arc<ProcessTree>,
        recent_gaps: Option<Arc<RecentGapsRing>>,
        log_writer: Option<LogWriter>,
    ) {
        self.arm_inner(
            audit_token,
            pending_gap,
            tree,
            recent_gaps,
            log_writer,
            TimeoutAction::RecordOnly,
        );
    }

    /// Arm a timeout that fail-closes the process when the `DylibLoaded`
    /// handshake never arrives. This is for coverage gaps whose process would
    /// otherwise continue outside Stentorian Guard enforcement.
    pub fn arm_enforced_with_forensics(
        &self,
        audit_token: AuditToken,
        pending_gap: CoverageGap,
        tree: Arc<ProcessTree>,
        recent_gaps: Option<Arc<RecentGapsRing>>,
        log_writer: Option<LogWriter>,
    ) {
        self.arm_inner(
            audit_token,
            pending_gap,
            tree,
            recent_gaps,
            log_writer,
            TimeoutAction::KillProcess,
        );
    }

    fn arm_inner(
        &self,
        audit_token: AuditToken,
        pending_gap: CoverageGap,
        tree: Arc<ProcessTree>,
        recent_gaps: Option<Arc<RecentGapsRing>>,
        log_writer: Option<LogWriter>,
        timeout_action: TimeoutAction,
    ) {
        let (tx, rx) = bounded::<()>(1);

        // Replace any prior pending timer for this token (the old tx drops
        // when the slot is replaced — the old worker thread sees rx
        // disconnected and silently exits without recording).
        let _old = self
            .pending
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(audit_token, tx);

        std::thread::spawn(move || {
            match rx.recv_timeout(Duration::from_millis(GAP_TIMEOUT_MS)) {
                Ok(()) | Err(crossbeam_channel::RecvTimeoutError::Disconnected) => {
                    // Cancellation signal received — DylibLoaded arrived in time.
                    // Do not record gap. A disconnected channel means this arm was replaced.
                }
                Err(crossbeam_channel::RecvTimeoutError::Timeout) => {
                    // No DylibLoaded within window → record the gap.
                    let _ = tree.set_coverage_gap(audit_token, pending_gap.clone());

                    // v0.3: forensic publication.
                    // Look up run_uuid from the node for GapInfo + LogRow.
                    let (run_uuid, binary_path) = match &pending_gap {
                        CoverageGap::ConfirmedHardened { binary_path, .. } => {
                            let run_uuid = tree
                                .get_node(&audit_token)
                                .map(|n| n.run_uuid.clone())
                                .unwrap_or_default();
                            (run_uuid, binary_path.clone())
                        }
                        CoverageGap::UnknownInjectionFailure { binary_path, .. } => {
                            let run_uuid = tree
                                .get_node(&audit_token)
                                .map(|n| n.run_uuid.clone())
                                .unwrap_or_default();
                            (run_uuid, binary_path.clone())
                        }
                        CoverageGap::EnvNotPropagated { binary_path, .. } => {
                            let run_uuid = tree
                                .get_node(&audit_token)
                                .map(|n| n.run_uuid.clone())
                                .unwrap_or_default();
                            (run_uuid, binary_path.clone())
                        }
                    };
                    let gap_kind_str: &'static str = match &pending_gap {
                        CoverageGap::ConfirmedHardened { .. } => "hardened-runtime",
                        CoverageGap::UnknownInjectionFailure { .. } => "unknown-injection-failure",
                        CoverageGap::EnvNotPropagated { .. } => "env-not-propagated",
                    };
                    let detected_at_ms = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX));
                    let binary_path_opt = if binary_path.is_empty() {
                        None
                    } else {
                        Some(binary_path.clone())
                    };
                    let gap_info = GapInfo {
                        run_uuid: run_uuid.clone(),
                        gap_kind: gap_kind_str.to_string(),
                        binary_path: binary_path_opt.clone(),
                        detected_at_ms,
                    };
                    if let Some(rg) = &recent_gaps {
                        rg.push(gap_info);
                    }
                    if let Some(lw) = &log_writer {
                        // WR-09: synthesize argv[0] from the ProcessNode's
                        // recorded binary_path so the gap row is forensically
                        // useful (an analyst needs SOMETHING to identify the
                        // process beyond pid + pidversion). ProcessNode does
                        // not record full argv or cwd in v1; document that
                        // limitation on the row by leaving cwd empty rather
                        // than fabricating a value.
                        let argv = if binary_path.is_empty() {
                            Vec::new()
                        } else {
                            vec![binary_path.clone()]
                        };
                        lw.send(LogRow::Gap(GapRecord {
                            schema_version: JSONL_SCHEMA_VERSION,
                            ts: now_rfc3339(),
                            run_uuid,
                            gap_kind: gap_kind_str,
                            process: crate::log_writer::ProcessCtxLog {
                                pid: audit_token.val[5],
                                pidversion: audit_token.val[7],
                                argv,
                                cwd: String::new(),
                            },
                            binary_path: binary_path_opt,
                        }));
                    }
                    timeout_action.apply(audit_token, &pending_gap);
                }
            }
        });
    }

    /// Cancel a pending timer. Returns true if there was a pending timer to cancel.
    pub fn cancel(&self, audit_token: &AuditToken) -> bool {
        let mut g = self
            .pending
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        match g.remove(audit_token) {
            Some(tx) => {
                let _ = tx.send(());
                true
            }
            None => false,
        }
    }

    #[must_use]
    pub fn pending_count(&self) -> usize {
        self.pending
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .len()
    }
}

impl TimeoutAction {
    fn apply(self, audit_token: AuditToken, gap: &CoverageGap) {
        match self {
            Self::RecordOnly => {}
            Self::KillProcess => kill_gap_process(audit_token, gap),
        }
    }
}

fn kill_gap_process(audit_token: AuditToken, gap: &CoverageGap) {
    if !matches!(
        gap,
        CoverageGap::ConfirmedHardened { .. } | CoverageGap::UnknownInjectionFailure { .. }
    ) {
        return;
    }

    let Some(pid) = audit_token_pid(audit_token) else {
        warn!(
            pid = audit_token.val[5],
            "coverage gap fail-closed skipped: invalid pid"
        );
        return;
    };

    if !pidversion_still_matches(pid, audit_token.val[7]) {
        warn!(
            pid,
            expected_pidversion = audit_token.val[7],
            "coverage gap fail-closed skipped: pidversion changed"
        );
        return;
    }

    let rc = unsafe { libc::kill(pid, libc::SIGKILL) };
    if rc == 0 {
        warn!(
            pid,
            pidversion = audit_token.val[7],
            gap_kind = gap_kind(gap),
            "coverage gap fail-closed: killed process after DylibLoaded timeout"
        );
        return;
    }

    let errno = last_errno();
    if errno == libc::ESRCH {
        debug!(
            pid,
            pidversion = audit_token.val[7],
            "coverage gap fail-closed skipped: process already exited"
        );
    } else {
        warn!(
            pid,
            pidversion = audit_token.val[7],
            errno,
            "coverage gap fail-closed failed to kill process"
        );
    }
}

fn audit_token_pid(audit_token: AuditToken) -> Option<libc::pid_t> {
    let pid = libc::pid_t::try_from(audit_token.val[5]).ok()?;
    (pid > 0).then_some(pid)
}

fn gap_kind(gap: &CoverageGap) -> &'static str {
    match gap {
        CoverageGap::ConfirmedHardened { .. } => "hardened-runtime",
        CoverageGap::UnknownInjectionFailure { .. } => "unknown-injection-failure",
        CoverageGap::EnvNotPropagated { .. } => "env-not-propagated",
    }
}

fn pidversion_still_matches(pid: libc::pid_t, expected_pidversion: u32) -> bool {
    if expected_pidversion == 0 {
        return true;
    }
    match kernel_pidversion(pid) {
        Some(actual) => actual == expected_pidversion,
        None => true,
    }
}
