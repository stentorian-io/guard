//! Sentinel domain types — ProcessIdentity, allowlist matcher, snapshot codec.

pub mod allowlist;
pub mod error;
pub mod identity;
pub mod snapshot;

pub use allowlist::{AllowlistEntry, MatchType, RuleKind, RuleTier, Verdict, evaluate_rule};
pub use error::Error;
pub use identity::{AuditToken, ProcessIdentity, audit_token_to_pid, audit_token_to_pidversion};
pub use snapshot::{SCHEMA_V1, SCHEMA_V2, Snapshot};
