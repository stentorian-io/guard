//! crates/sentinel-daemon/src/baseline_staging.rs
//!
//! Phase 3 plan 03-07 — per-run baseline accumulator (POL-04 / D-58).
//!
//! In `sentinel wrap --baseline` mode, every allow-and-log decision is recorded
//! into a per-run-uuid Vec<ProposedRule>. On tracked-root exit, the BaselineCommit
//! IPC handler `take()`s the entries and returns them to the CLI for diff-confirm.
//! Curated denies and hard rules (D-25/D-26) still fire and are NOT staged.

use std::collections::HashMap;
use std::sync::Mutex;

use sentinel_ipc::ProposedRule;

#[derive(Default)]
pub struct BaselineStaging {
    inner: Mutex<HashMap<String, Vec<ProposedRule>>>,
}

impl BaselineStaging {
    pub fn new() -> Self {
        Self::default()
    }

    /// Record an allow-and-log entry. Idempotent across (run_uuid, match_type, pattern):
    /// repeated calls with the same triple do not duplicate the entry.
    pub fn record_allow(&self, run_uuid: &str, match_type: &str, pattern: &str, reason: &str) {
        let mut g = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        let entries = g.entry(run_uuid.to_string()).or_insert_with(Vec::new);
        if entries
            .iter()
            .any(|r| r.match_type == match_type && r.pattern == pattern)
        {
            return;
        }
        entries.push(ProposedRule {
            match_type: match_type.to_string(),
            pattern: pattern.to_string(),
            reason: reason.to_string(),
        });
    }

    /// Consume the staging for a run. Called once at BaselineCommit.
    pub fn take(&self, run_uuid: &str) -> Option<Vec<ProposedRule>> {
        let mut g = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        g.remove(run_uuid)
    }

    pub fn peek_count(&self, run_uuid: &str) -> usize {
        let g = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        g.get(run_uuid).map(|v| v.len()).unwrap_or(0)
    }
}
