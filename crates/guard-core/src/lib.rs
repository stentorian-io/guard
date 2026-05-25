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
pub mod trusted_signers;

pub use allowlist::{AllowlistEntry, MatchType, RuleKind, RuleTier, Verdict, evaluate_rule};
pub use error::Error;
pub use identity::{AuditToken, ProcessIdentity, audit_token_to_pid, audit_token_to_pidversion};
pub use policy::{
    SourceKind, evaluate_policy, has_user_allow, is_cloud_metadata_host, is_cloud_metadata_ip,
    is_loopback_host, is_loopback_ip,
};
pub use rule_signature::{
    MANAGEMENT_ACTION_PAYLOAD_SCHEMA_V1, ManagementActionPayloadV1,
    RULE_SIGNATURE_PAYLOAD_SCHEMA_V1, RULE_SIGNATURE_SCHEME_ECDSA_P256_SHA256, RuleSignatureError,
    RuleSignaturePayloadV1, RuleSignaturePolicy, RuleSignatureV1, SIGNER_KIND_SECURE_ENCLAVE,
    SIGNER_KIND_SECURITY_KEY, SIGNER_KIND_TEST_SIMULATOR, SIGNER_KIND_TPM,
    SNAPSHOT_SIGNATURE_PAYLOAD_SCHEMA_V1, SnapshotSignaturePayloadV1, SnapshotSignatureV1,
    canonical_management_action_payload_bytes, canonical_rule_payload_bytes,
    canonical_snapshot_payload_bytes, sha256_hex, verify_management_action_signature,
    verify_rule_signature, verify_snapshot_signature,
};
pub use snapshot::{SCHEMA_V1, SCHEMA_V2, Snapshot};
pub use snapshot_build::{SnapshotBuildInput, build_snapshot, build_snapshot_bytes};
pub use trusted_signers::{
    TrustedSigner, TrustedSignerManifestError, first_trusted_signer, parse_trusted_signers,
    trusted_signer_matches,
};
