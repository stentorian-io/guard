//! Two-phase coverage-gap detector (D-34).
//!
//! When the daemon receives an ExecEvent and the calling process's csops
//! flags indicate hardened-runtime, this module schedules a 500 ms timer
//! that watches for a matching DylibLoaded arrival. If none arrives, the
//! gap is recorded on the parent node in the ProcessTree. If DylibLoaded
//! arrives in time (cancel called), the gap is NOT recorded.
//!
//! Implementation: one std::thread per armed timer. Each thread sleeps up
//! to 500 ms or until a cancel signal arrives via crossbeam-channel.
//! Threads are short-lived (≤ 500 ms) so peak thread count is bounded
//! by ExecEvent rate × 500 ms.

use crate::tracked::{CoverageGap, ProcessTree};
use crossbeam_channel::{bounded, Sender};
use sentinel_core::AuditToken;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

pub const GAP_TIMEOUT_MS: u64 = 500;

#[derive(Default)]
pub struct GapDetector {
    pending: Mutex<HashMap<AuditToken, Sender<()>>>,
}

impl GapDetector {
    pub fn new() -> Self {
        Self::default()
    }

    /// Arm a timeout. If `cancel(audit_token)` is not called within
    /// GAP_TIMEOUT_MS, sets `pending_gap` on the node in `tree`.
    /// Re-arming the same token cancels the prior timer.
    pub fn arm(
        &self,
        audit_token: AuditToken,
        pending_gap: CoverageGap,
        tree: Arc<ProcessTree>,
    ) {
        let (tx, rx) = bounded::<()>(1);

        // Replace any prior pending timer for this token (the old tx drops
        // when the slot is replaced — the old worker thread sees rx
        // disconnected and silently exits without recording).
        let _old = self.pending.lock().expect("gap_detector pending").insert(audit_token, tx);

        std::thread::spawn(move || {
            match rx.recv_timeout(Duration::from_millis(GAP_TIMEOUT_MS)) {
                Ok(()) => {
                    // Cancellation signal received — DylibLoaded arrived in time.
                    // Do not record gap.
                }
                Err(crossbeam_channel::RecvTimeoutError::Timeout) => {
                    // No DylibLoaded within window → record the gap.
                    let _ = tree.set_coverage_gap(audit_token, pending_gap);
                }
                Err(crossbeam_channel::RecvTimeoutError::Disconnected) => {
                    // Detector dropped tx (re-armed or detector freed).
                    // Do not record — the new arm owns this slot now.
                }
            }
        });
    }

    /// Cancel a pending timer. Returns true if there was a pending timer to cancel.
    pub fn cancel(&self, audit_token: &AuditToken) -> bool {
        let mut g = self.pending.lock().expect("gap_detector pending");
        match g.remove(audit_token) {
            Some(tx) => {
                let _ = tx.send(());
                true
            }
            None => false,
        }
    }

    pub fn pending_count(&self) -> usize {
        self.pending.lock().expect("gap_detector pending").len()
    }
}
