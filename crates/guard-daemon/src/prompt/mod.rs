//! crates/guard-daemon/src/prompt/mod.rs
//!
//! v0.3 — daemon-side prompt support helpers.

pub mod dedup;
pub mod recent_gaps;
pub mod suggested_rules;

pub use dedup::{CoalesceOutcome, PromptDedup};
pub use recent_gaps::RecentGapsRing;
pub use suggested_rules::generate_suggested_rules;
