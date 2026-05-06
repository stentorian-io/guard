//! crates/sentinel-daemon/src/prompt/mod.rs
//!
//! Phase 3 — daemon-side prompt support helpers.

pub mod dedup;
pub mod suggested_rules;
pub mod recent_gaps;

pub use dedup::{CoalesceOutcome, PromptDedup};
pub use recent_gaps::RecentGapsRing;
pub use suggested_rules::generate_suggested_rules;
