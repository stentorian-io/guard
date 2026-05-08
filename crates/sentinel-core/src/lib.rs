//! Sentinel domain types — ProcessIdentity, allowlist matcher, snapshot codec.

pub mod allowlist;
pub mod error;
pub mod identity;
pub mod osv_match;
pub mod policy;
pub mod policy_file;
pub mod policy_file_writer;
pub mod snapshot;

pub use allowlist::{AllowlistEntry, MatchType, RuleKind, RuleTier, Verdict, evaluate_rule};
pub use error::Error;
pub use identity::{AuditToken, ProcessIdentity, audit_token_to_pid, audit_token_to_pidversion};
pub use policy::{
    SourceKind, evaluate_policy, is_cloud_metadata_host, is_cloud_metadata_ip, is_loopback_host,
    is_loopback_ip,
};
pub use policy_file::{find_sentinel_toml, PolicyFileError, PolicyRule, SentinelToml, MAX_DEPTH};
pub use policy_file_writer::{WriteError, append_rule, append_rules};
pub use snapshot::{SCHEMA_V1, SCHEMA_V2, Snapshot};
