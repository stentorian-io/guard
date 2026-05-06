//! In-memory tracked-roots set.
//!
//! Phase 1 stores AuditTokens (full 8 × u32) so `(pid, pidversion)` uniqueness
//! is preserved per ENF-08. Phase 2 grows this into the process-tree supervisor.

use sentinel_core::AuditToken;
use std::collections::HashSet;
use std::sync::Mutex;

#[derive(Default)]
pub struct TrackedRoots {
    inner: Mutex<HashSet<AuditToken>>,
}

impl TrackedRoots {
    pub fn new() -> Self {
        Self::default()
    }

    /// Inserts the token. Returns true if newly inserted, false if already present
    /// (idempotent — duplicate RegisterRoot for the same audit token is fine).
    pub fn insert(&self, token: AuditToken) -> bool {
        self.inner.lock().expect("tracked roots mutex").insert(token)
    }

    pub fn contains(&self, token: &AuditToken) -> bool {
        self.inner.lock().expect("tracked roots mutex").contains(token)
    }

    pub fn len(&self) -> usize {
        self.inner.lock().expect("tracked roots mutex").len()
    }

    pub fn is_empty(&self) -> bool {
        self.inner.lock().expect("tracked roots mutex").is_empty()
    }
}
