//! Sentinel domain types — ProcessIdentity, allowlist matcher, snapshot codec.

pub mod allowlist;
pub mod error;
pub mod identity;
pub mod snapshot;

pub use allowlist::{AllowlistEntry, Verdict, match_hostname};
pub use error::Error;
pub use identity::{AuditToken, ProcessIdentity, audit_token_to_pid, audit_token_to_pidversion};
pub use snapshot::{Snapshot, SCHEMA_V1};
