//! crates/sentinel-daemon/src/prompt/dedup.rs
//!
//! v0.3 — prompt dedup window.
//!
//! Coalesces identical (run_uuid, host, port) PromptRequest tuples within a 5-second
//! window. Mirrors v0.2's gap_detector.rs Mutex<HashMap> + Instant-TTL pattern.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

pub const WINDOW: Duration = Duration::from_secs(5);

#[derive(Default)]
pub struct PromptDedup {
    pending: Mutex<HashMap<(String, String, u16), (String, Instant)>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CoalesceOutcome {
    Fresh,
    Existing(String), // existing prompt_id
}

impl PromptDedup {
    pub fn new() -> Self {
        Self::default()
    }

    /// Production entry point — uses Instant::now() as TTL anchor.
    pub fn coalesce(&self, run_uuid: &str, host: &str, port: u16, new_prompt_id: &str)
        -> CoalesceOutcome
    {
        self.coalesce_with_now(Instant::now(), run_uuid, host, port, new_prompt_id)
    }

    /// Test-friendly variant: caller supplies the time anchor.
    pub fn coalesce_with_now(
        &self,
        now: Instant,
        run_uuid: &str,
        host: &str,
        port: u16,
        new_prompt_id: &str,
    ) -> CoalesceOutcome {
        let mut g = self.pending.lock().unwrap_or_else(|p| p.into_inner());
        let key = (run_uuid.to_string(), host.to_string(), port);
        if let Some((existing_id, expires)) = g.get(&key) {
            if *expires > now {
                return CoalesceOutcome::Existing(existing_id.clone());
            }
        }
        g.insert(key, (new_prompt_id.to_string(), now + WINDOW));
        CoalesceOutcome::Fresh
    }

    /// Drop the dedup entry — called when PromptResponse arrives or PromptCancel fires.
    pub fn forget(&self, run_uuid: &str, host: &str, port: u16) {
        let mut g = self.pending.lock().unwrap_or_else(|p| p.into_inner());
        g.remove(&(run_uuid.to_string(), host.to_string(), port));
    }

    /// Remove all expired entries; called opportunistically.
    pub fn gc_expired(&self) {
        let now = Instant::now();
        let mut g = self.pending.lock().unwrap_or_else(|p| p.into_inner());
        g.retain(|_, (_, expires)| *expires > now);
    }
}
