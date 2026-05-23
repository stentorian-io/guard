//! Stentorian Guard domain types — ProcessIdentity, allowlist matcher, snapshot codec.

pub mod allowlist;
pub mod env_filter;
pub mod error;
pub mod identity;
pub mod lockfile;
pub mod paths;
pub mod policy;
pub mod rule_signature;
pub mod snapshot;
pub mod snapshot_build;

pub use allowlist::{evaluate_rule, AllowlistEntry, MatchType, RuleKind, RuleTier, Verdict};
pub use error::Error;
pub use identity::{audit_token_to_pid, audit_token_to_pidversion, AuditToken, ProcessIdentity};
pub use policy::{
    evaluate_policy, has_user_allow, is_cloud_metadata_host, is_cloud_metadata_ip,
    is_loopback_host, is_loopback_ip, SourceKind,
};
pub use rule_signature::{
    canonical_rule_payload_bytes, sha256_hex, verify_rule_signature, RuleSignatureError,
    RuleSignaturePayloadV1, RuleSignaturePolicy, RuleSignatureV1, RULE_SIGNATURE_PAYLOAD_SCHEMA_V1,
    RULE_SIGNATURE_SCHEME_ECDSA_P256_SHA256, SIGNER_KIND_SECURE_ENCLAVE, SIGNER_KIND_SECURITY_KEY,
    SIGNER_KIND_TEST_SIMULATOR, SIGNER_KIND_TPM,
};
pub use snapshot::{Snapshot, SCHEMA_V1, SCHEMA_V2};
pub use snapshot_build::{build_snapshot, build_snapshot_bytes, SnapshotBuildInput};
