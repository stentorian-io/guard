//! crates/guard-daemon/src/prompt/recent_gaps.rs
//!
//! v0.3 — bounded ring of recent coverage gaps for `StatusReply`
//! (RESEARCH.md Open Question §9). Capacity 100 newest-wins.

use std::collections::VecDeque;
use std::sync::Mutex;

use guard_ipc::GapInfo;

pub const CAPACITY: usize = 100;

#[derive(Default)]
pub struct RecentGapsRing {
    inner: Mutex<VecDeque<GapInfo>>,
}

impl RecentGapsRing {
    #[must_use]
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(VecDeque::with_capacity(CAPACITY)),
        }
    }

    pub fn push(&self, gap: GapInfo) {
        let mut g = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if g.len() >= CAPACITY {
            g.pop_front();
        }
        g.push_back(gap);
    }

    /// Returns oldest-to-newest snapshot.
    pub fn snapshot(&self) -> Vec<GapInfo> {
        let g = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        g.iter().cloned().collect()
    }

    pub fn len(&self) -> usize {
        let g = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        g.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}
