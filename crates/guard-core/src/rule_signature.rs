//! Canonical signed user-rule payloads and verification policy.
//!
//! Issue #31 requires persisted baseline/user rules to be authenticated by a
//! signer the daemon can verify but cannot forge with. Production policy accepts
//! only hardware-backed signer kinds; CI may opt into the explicit
//! `test-simulator` signer kind to exercise tamper detection without pretending
//! hosted CI has real signing hardware.

use p256::ecdsa::signature::Verifier;
use p256::ecdsa::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const RULE_SIGNATURE_PAYLOAD_SCHEMA_V1: u16 = 1;
pub const SNAPSHOT_SIGNATURE_PAYLOAD_SCHEMA_V1: u16 = 1;
pub const RULE_SIGNATURE_SCHEME_ECDSA_P256_SHA256: &str = "ecdsa-p256-sha256";
pub const SIGNER_KIND_SECURE_ENCLAVE: &str = "secure-enclave";
pub const SIGNER_KIND_SECURITY_KEY: &str = "security-key";
pub const SIGNER_KIND_TPM: &str = "tpm";
pub const SIGNER_KIND_TEST_SIMULATOR: &str = "test-simulator";

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct RuleSignaturePayloadV1 {
    pub schema_version: u16,
    pub kind: String,
    pub match_type: String,
    pub pattern: String,
    pub reason: String,
    pub created_at_unix_ms: i64,
    pub origin: String,
    pub run_uuid: Option<String>,
}

impl RuleSignaturePayloadV1 {
    pub fn new(
        kind: impl Into<String>,
        match_type: impl Into<String>,
        pattern: impl Into<String>,
        reason: impl Into<String>,
        created_at_unix_ms: i64,
        origin: impl Into<String>,
        run_uuid: Option<String>,
    ) -> Self {
        Self {
            schema_version: RULE_SIGNATURE_PAYLOAD_SCHEMA_V1,
            kind: kind.into(),
            match_type: match_type.into(),
            pattern: pattern.into(),
            reason: reason.into(),
            created_at_unix_ms,
            origin: origin.into(),
            run_uuid,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct RuleSignatureV1 {
    pub scheme: String,
    pub signer_kind: String,
    pub public_key_x963: Vec<u8>,
    pub public_key_sha256: String,
    pub signature_der: Vec<u8>,
    pub signed_payload_sha256: String,
    pub signature_created_at_unix_ms: i64,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct SnapshotSignaturePayloadV1 {
    pub schema_version: u16,
    pub run_uuid: String,
    pub snapshot_sha256: String,
    pub generated_at_unix_ms: i64,
}

impl SnapshotSignaturePayloadV1 {
    pub fn new(
        run_uuid: impl Into<String>,
        snapshot_sha256: impl Into<String>,
        generated_at_unix_ms: i64,
    ) -> Self {
        Self {
            schema_version: SNAPSHOT_SIGNATURE_PAYLOAD_SCHEMA_V1,
            run_uuid: run_uuid.into(),
            snapshot_sha256: snapshot_sha256.into(),
            generated_at_unix_ms,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct SnapshotSignatureV1 {
    pub scheme: String,
    pub signer_kind: String,
    pub public_key_x963: Vec<u8>,
    pub public_key_sha256: String,
    pub signature_der: Vec<u8>,
    pub signed_payload_sha256: String,
    pub signature_created_at_unix_ms: i64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RuleSignaturePolicy {
    Production,
    AllowTestSimulator,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum RuleSignatureError {
    #[error("canonical payload encode failed: {0}")]
    Encode(String),
    #[error("unsupported rule signature payload schema: {0}")]
    UnsupportedPayloadSchema(u16),
    #[error("unsupported rule signature scheme: {0}")]
    UnsupportedScheme(String),
    #[error("unsupported rule signer kind: {0}")]
    UnsupportedSignerKind(String),
    #[error("public key hash mismatch")]
    PublicKeyHashMismatch,
    #[error("signed payload hash mismatch")]
    PayloadHashMismatch,
    #[error("invalid public key")]
    InvalidPublicKey,
    #[error("invalid signature encoding")]
    InvalidSignatureEncoding,
    #[error("signature mismatch")]
    SignatureMismatch,
}

pub fn canonical_rule_payload_bytes(
    payload: &RuleSignaturePayloadV1,
) -> Result<Vec<u8>, RuleSignatureError> {
    let mut bytes = Vec::new();
    ciborium::into_writer(payload, &mut bytes)
        .map_err(|e| RuleSignatureError::Encode(e.to_string()))?;
    Ok(bytes)
}

pub fn canonical_snapshot_payload_bytes(
    payload: &SnapshotSignaturePayloadV1,
) -> Result<Vec<u8>, RuleSignatureError> {
    let mut bytes = Vec::new();
    ciborium::into_writer(payload, &mut bytes)
        .map_err(|e| RuleSignatureError::Encode(e.to_string()))?;
    Ok(bytes)
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    hex_lower(&Sha256::digest(bytes))
}

pub fn verify_rule_signature(
    payload: &RuleSignaturePayloadV1,
    signature: &RuleSignatureV1,
    policy: RuleSignaturePolicy,
) -> Result<(), RuleSignatureError> {
    if payload.schema_version != RULE_SIGNATURE_PAYLOAD_SCHEMA_V1 {
        return Err(RuleSignatureError::UnsupportedPayloadSchema(
            payload.schema_version,
        ));
    }
    if signature.scheme != RULE_SIGNATURE_SCHEME_ECDSA_P256_SHA256 {
        return Err(RuleSignatureError::UnsupportedScheme(
            signature.scheme.clone(),
        ));
    }
    if !signer_kind_allowed(&signature.signer_kind, policy) {
        return Err(RuleSignatureError::UnsupportedSignerKind(
            signature.signer_kind.clone(),
        ));
    }
    if sha256_hex(&signature.public_key_x963) != signature.public_key_sha256 {
        return Err(RuleSignatureError::PublicKeyHashMismatch);
    }

    let payload_bytes = canonical_rule_payload_bytes(payload)?;
    if sha256_hex(&payload_bytes) != signature.signed_payload_sha256 {
        return Err(RuleSignatureError::PayloadHashMismatch);
    }

    let verifying_key = VerifyingKey::from_sec1_bytes(&signature.public_key_x963)
        .map_err(|_| RuleSignatureError::InvalidPublicKey)?;
    let sig = Signature::from_der(&signature.signature_der)
        .map_err(|_| RuleSignatureError::InvalidSignatureEncoding)?;
    verifying_key
        .verify(&payload_bytes, &sig)
        .map_err(|_| RuleSignatureError::SignatureMismatch)
}

pub fn verify_snapshot_signature(
    payload: &SnapshotSignaturePayloadV1,
    signature: &SnapshotSignatureV1,
    policy: RuleSignaturePolicy,
) -> Result<(), RuleSignatureError> {
    if payload.schema_version != SNAPSHOT_SIGNATURE_PAYLOAD_SCHEMA_V1 {
        return Err(RuleSignatureError::UnsupportedPayloadSchema(
            payload.schema_version,
        ));
    }
    if signature.scheme != RULE_SIGNATURE_SCHEME_ECDSA_P256_SHA256 {
        return Err(RuleSignatureError::UnsupportedScheme(
            signature.scheme.clone(),
        ));
    }
    if !signer_kind_allowed(&signature.signer_kind, policy) {
        return Err(RuleSignatureError::UnsupportedSignerKind(
            signature.signer_kind.clone(),
        ));
    }
    if sha256_hex(&signature.public_key_x963) != signature.public_key_sha256 {
        return Err(RuleSignatureError::PublicKeyHashMismatch);
    }

    let payload_bytes = canonical_snapshot_payload_bytes(payload)?;
    if sha256_hex(&payload_bytes) != signature.signed_payload_sha256 {
        return Err(RuleSignatureError::PayloadHashMismatch);
    }

    let verifying_key = VerifyingKey::from_sec1_bytes(&signature.public_key_x963)
        .map_err(|_| RuleSignatureError::InvalidPublicKey)?;
    let sig = Signature::from_der(&signature.signature_der)
        .map_err(|_| RuleSignatureError::InvalidSignatureEncoding)?;
    verifying_key
        .verify(&payload_bytes, &sig)
        .map_err(|_| RuleSignatureError::SignatureMismatch)
}

fn signer_kind_allowed(kind: &str, policy: RuleSignaturePolicy) -> bool {
    match policy {
        RuleSignaturePolicy::Production => matches!(
            kind,
            SIGNER_KIND_SECURE_ENCLAVE | SIGNER_KIND_SECURITY_KEY | SIGNER_KIND_TPM
        ),
        RuleSignaturePolicy::AllowTestSimulator => matches!(
            kind,
            SIGNER_KIND_SECURE_ENCLAVE
                | SIGNER_KIND_SECURITY_KEY
                | SIGNER_KIND_TPM
                | SIGNER_KIND_TEST_SIMULATOR
        ),
    }
}

fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 0x0f) as usize] as char);
    }
    s
}

#[cfg(any(test, feature = "test-signer"))]
pub mod test_support {
    use super::*;
    use p256::ecdsa::signature::Signer;
    use p256::ecdsa::SigningKey;

    pub fn sign_with_test_simulator(
        payload: &RuleSignaturePayloadV1,
    ) -> Result<RuleSignatureV1, RuleSignatureError> {
        // Fixed non-zero scalar. This is intentionally deterministic and test-only.
        let signing_key =
            SigningKey::from_slice(&[7u8; 32]).map_err(|_| RuleSignatureError::InvalidPublicKey)?;
        let payload_bytes = canonical_rule_payload_bytes(payload)?;
        let signature: Signature = signing_key.sign(&payload_bytes);
        let verifying_key = signing_key.verifying_key();
        let public_key_x963 = verifying_key.to_encoded_point(false).as_bytes().to_vec();
        Ok(RuleSignatureV1 {
            scheme: RULE_SIGNATURE_SCHEME_ECDSA_P256_SHA256.to_string(),
            signer_kind: SIGNER_KIND_TEST_SIMULATOR.to_string(),
            public_key_sha256: sha256_hex(&public_key_x963),
            public_key_x963,
            signature_der: signature.to_der().as_bytes().to_vec(),
            signed_payload_sha256: sha256_hex(&payload_bytes),
            signature_created_at_unix_ms: payload.created_at_unix_ms,
        })
    }

    pub fn sign_snapshot_with_test_simulator(
        payload: &SnapshotSignaturePayloadV1,
    ) -> Result<SnapshotSignatureV1, RuleSignatureError> {
        // Fixed non-zero scalar. This is intentionally deterministic and test-only.
        let signing_key =
            SigningKey::from_slice(&[7u8; 32]).map_err(|_| RuleSignatureError::InvalidPublicKey)?;
        let payload_bytes = canonical_snapshot_payload_bytes(payload)?;
        let signature: Signature = signing_key.sign(&payload_bytes);
        let verifying_key = signing_key.verifying_key();
        let public_key_x963 = verifying_key.to_encoded_point(false).as_bytes().to_vec();
        Ok(SnapshotSignatureV1 {
            scheme: RULE_SIGNATURE_SCHEME_ECDSA_P256_SHA256.to_string(),
            signer_kind: SIGNER_KIND_TEST_SIMULATOR.to_string(),
            public_key_sha256: sha256_hex(&public_key_x963),
            public_key_x963,
            signature_der: signature.to_der().as_bytes().to_vec(),
            signed_payload_sha256: sha256_hex(&payload_bytes),
            signature_created_at_unix_ms: payload.generated_at_unix_ms,
        })
    }
}
