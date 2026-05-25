//! Canonical signed user-rule payloads and verification policy.
//!
//! Issue #31 requires persisted baseline/user rules to be authenticated by a
//! signer the daemon can verify but cannot forge with. Production policy uses
//! ML-DSA-65 so first-release project-owned policy signatures are post-quantum
//! from the start. CI may opt into the explicit `test-simulator` signer kind to
//! exercise tamper detection without claiming production signing coverage.

use pqcrypto_mldsa::mldsa65;
use pqcrypto_traits::sign::{DetachedSignature as _, PublicKey as _};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const RULE_SIGNATURE_PAYLOAD_SCHEMA_V1: u16 = 1;
pub const SNAPSHOT_SIGNATURE_PAYLOAD_SCHEMA_V1: u16 = 1;
pub const MANAGEMENT_ACTION_PAYLOAD_SCHEMA_V1: u16 = 1;
pub const RULE_SIGNATURE_SCHEME_ML_DSA_65_SHA256: &str = "ml-dsa-65-sha256";
pub const SIGNER_KIND_SOFTWARE_ML_DSA: &str = "software-ml-dsa";
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

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ManagementActionPayloadV1 {
    pub schema_version: u16,
    pub action: String,
    pub pattern: String,
    pub reason: String,
    pub created_at_unix_ms: i64,
}

impl ManagementActionPayloadV1 {
    pub fn new(
        action: impl Into<String>,
        pattern: impl Into<String>,
        reason: impl Into<String>,
        created_at_unix_ms: i64,
    ) -> Self {
        Self {
            schema_version: MANAGEMENT_ACTION_PAYLOAD_SCHEMA_V1,
            action: action.into(),
            pattern: pattern.into(),
            reason: reason.into(),
            created_at_unix_ms,
        }
    }
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

pub fn canonical_management_action_payload_bytes(
    payload: &ManagementActionPayloadV1,
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

    verify_signature_bytes(&payload_bytes, signature, policy)
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

    verify_snapshot_signature_bytes(&payload_bytes, signature, policy)
}

pub fn verify_management_action_signature(
    payload: &ManagementActionPayloadV1,
    signature: &RuleSignatureV1,
    policy: RuleSignaturePolicy,
) -> Result<(), RuleSignatureError> {
    if payload.schema_version != MANAGEMENT_ACTION_PAYLOAD_SCHEMA_V1 {
        return Err(RuleSignatureError::UnsupportedPayloadSchema(
            payload.schema_version,
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

    let payload_bytes = canonical_management_action_payload_bytes(payload)?;
    if sha256_hex(&payload_bytes) != signature.signed_payload_sha256 {
        return Err(RuleSignatureError::PayloadHashMismatch);
    }

    verify_signature_bytes(&payload_bytes, signature, policy)
}

fn verify_signature_bytes(
    payload_bytes: &[u8],
    signature: &RuleSignatureV1,
    policy: RuleSignaturePolicy,
) -> Result<(), RuleSignatureError> {
    verify_detached_signature_bytes(
        payload_bytes,
        &signature.scheme,
        &signature.signer_kind,
        &signature.public_key_x963,
        &signature.signature_der,
        policy,
    )
}

fn verify_snapshot_signature_bytes(
    payload_bytes: &[u8],
    signature: &SnapshotSignatureV1,
    policy: RuleSignaturePolicy,
) -> Result<(), RuleSignatureError> {
    verify_detached_signature_bytes(
        payload_bytes,
        &signature.scheme,
        &signature.signer_kind,
        &signature.public_key_x963,
        &signature.signature_der,
        policy,
    )
}

fn verify_detached_signature_bytes(
    payload_bytes: &[u8],
    scheme: &str,
    _signer_kind: &str,
    public_key: &[u8],
    signature: &[u8],
    _policy: RuleSignaturePolicy,
) -> Result<(), RuleSignatureError> {
    match scheme {
        RULE_SIGNATURE_SCHEME_ML_DSA_65_SHA256 => {
            let public_key = mldsa65::PublicKey::from_bytes(public_key)
                .map_err(|_| RuleSignatureError::InvalidPublicKey)?;
            let signature = mldsa65::DetachedSignature::from_bytes(signature)
                .map_err(|_| RuleSignatureError::InvalidSignatureEncoding)?;
            mldsa65::verify_detached_signature(&signature, payload_bytes, &public_key)
                .map_err(|_| RuleSignatureError::SignatureMismatch)
        }
        other => Err(RuleSignatureError::UnsupportedScheme(other.to_string())),
    }
}

fn signer_kind_allowed(kind: &str, policy: RuleSignaturePolicy) -> bool {
    match policy {
        RuleSignaturePolicy::Production => kind == SIGNER_KIND_SOFTWARE_ML_DSA,
        RuleSignaturePolicy::AllowTestSimulator => matches!(
            kind,
            SIGNER_KIND_SOFTWARE_ML_DSA
                | SIGNER_KIND_SECURE_ENCLAVE
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
    use pqcrypto_traits::sign::SecretKey as _;
    use std::path::Path;
    use std::sync::OnceLock;

    const TEST_ML_DSA_KEYPAIR_FILENAME: &str = "test-ml-dsa-65-signer.key";
    static TEST_ML_DSA_KEYPAIR: OnceLock<(Vec<u8>, Vec<u8>)> = OnceLock::new();

    pub fn install_test_simulator_signer(
        state_dir: &Path,
    ) -> Result<(String, String, Vec<u8>), RuleSignatureError> {
        let key_path = state_dir.join(TEST_ML_DSA_KEYPAIR_FILENAME);
        if !key_path.exists() {
            let (public_key, secret_key) = mldsa65::keypair();
            let content = format!(
                "public_key_hex={}\nsecret_key_hex={}\n",
                hex_lower(public_key.as_bytes()),
                hex_lower(secret_key.as_bytes())
            );
            std::fs::write(&key_path, content)
                .map_err(|e| RuleSignatureError::Encode(e.to_string()))?;
        }

        let (public_key_x963, _) = read_test_keypair_bytes(&key_path)?;
        Ok((
            sha256_hex(&public_key_x963),
            SIGNER_KIND_TEST_SIMULATOR.to_string(),
            public_key_x963,
        ))
    }

    pub fn test_simulator_public_signer() -> Result<(String, String, Vec<u8>), RuleSignatureError> {
        let (public_key_x963, _) = test_keypair_bytes()?;
        Ok((
            sha256_hex(&public_key_x963),
            SIGNER_KIND_TEST_SIMULATOR.to_string(),
            public_key_x963,
        ))
    }

    pub fn sign_with_test_simulator(
        payload: &RuleSignaturePayloadV1,
    ) -> Result<RuleSignatureV1, RuleSignatureError> {
        let payload_bytes = canonical_rule_payload_bytes(payload)?;
        let (public_key_x963, secret_key) = test_keypair_bytes()?;
        let secret_key = test_secret_key(&secret_key)?;
        let signature = mldsa65::detached_sign(&payload_bytes, &secret_key);
        Ok(RuleSignatureV1 {
            scheme: RULE_SIGNATURE_SCHEME_ML_DSA_65_SHA256.to_string(),
            signer_kind: SIGNER_KIND_TEST_SIMULATOR.to_string(),
            public_key_sha256: sha256_hex(&public_key_x963),
            public_key_x963,
            signature_der: signature.as_bytes().to_vec(),
            signed_payload_sha256: sha256_hex(&payload_bytes),
            signature_created_at_unix_ms: payload.created_at_unix_ms,
        })
    }

    pub fn sign_snapshot_with_test_simulator(
        payload: &SnapshotSignaturePayloadV1,
    ) -> Result<SnapshotSignatureV1, RuleSignatureError> {
        let payload_bytes = canonical_snapshot_payload_bytes(payload)?;
        let (public_key_x963, secret_key) = test_keypair_bytes()?;
        let secret_key = test_secret_key(&secret_key)?;
        let signature = mldsa65::detached_sign(&payload_bytes, &secret_key);
        Ok(SnapshotSignatureV1 {
            scheme: RULE_SIGNATURE_SCHEME_ML_DSA_65_SHA256.to_string(),
            signer_kind: SIGNER_KIND_TEST_SIMULATOR.to_string(),
            public_key_sha256: sha256_hex(&public_key_x963),
            public_key_x963,
            signature_der: signature.as_bytes().to_vec(),
            signed_payload_sha256: sha256_hex(&payload_bytes),
            signature_created_at_unix_ms: payload.generated_at_unix_ms,
        })
    }

    pub fn sign_management_action_with_test_simulator(
        payload: &ManagementActionPayloadV1,
    ) -> Result<RuleSignatureV1, RuleSignatureError> {
        let payload_bytes = canonical_management_action_payload_bytes(payload)?;
        let (public_key_x963, secret_key) = test_keypair_bytes()?;
        let secret_key = test_secret_key(&secret_key)?;
        let signature = mldsa65::detached_sign(&payload_bytes, &secret_key);
        Ok(RuleSignatureV1 {
            scheme: RULE_SIGNATURE_SCHEME_ML_DSA_65_SHA256.to_string(),
            signer_kind: SIGNER_KIND_TEST_SIMULATOR.to_string(),
            public_key_sha256: sha256_hex(&public_key_x963),
            public_key_x963,
            signature_der: signature.as_bytes().to_vec(),
            signed_payload_sha256: sha256_hex(&payload_bytes),
            signature_created_at_unix_ms: payload.created_at_unix_ms,
        })
    }

    fn test_keypair_bytes() -> Result<(Vec<u8>, Vec<u8>), RuleSignatureError> {
        if let Some(path) = test_keypair_path_from_state_dir() {
            return read_test_keypair_bytes(&path);
        }
        Ok(TEST_ML_DSA_KEYPAIR
            .get_or_init(|| {
                let (public_key, secret_key) = mldsa65::keypair();
                (
                    public_key.as_bytes().to_vec(),
                    secret_key.as_bytes().to_vec(),
                )
            })
            .clone())
    }

    fn test_secret_key(secret_key: &[u8]) -> Result<mldsa65::SecretKey, RuleSignatureError> {
        mldsa65::SecretKey::from_bytes(secret_key).map_err(|_| RuleSignatureError::InvalidPublicKey)
    }

    fn test_keypair_path_from_state_dir() -> Option<std::path::PathBuf> {
        let state_dir = std::env::var_os(crate::paths::ENV_STATE_DIR)?;
        Some(Path::new(&state_dir).join(TEST_ML_DSA_KEYPAIR_FILENAME))
    }

    fn read_test_keypair_bytes(path: &Path) -> Result<(Vec<u8>, Vec<u8>), RuleSignatureError> {
        let content =
            std::fs::read_to_string(path).map_err(|e| RuleSignatureError::Encode(e.to_string()))?;
        let public_key = decode_hex(parse_field(&content, "public_key_hex")?)?;
        let secret_key = decode_hex(parse_field(&content, "secret_key_hex")?)?;
        Ok((public_key, secret_key))
    }

    fn parse_field<'a>(content: &'a str, key: &str) -> Result<&'a str, RuleSignatureError> {
        let prefix = format!("{key}=");
        content
            .lines()
            .find_map(|line| line.strip_prefix(&prefix))
            .ok_or_else(|| RuleSignatureError::Encode(format!("test signer key omitted {key}")))
    }

    fn decode_hex(s: &str) -> Result<Vec<u8>, RuleSignatureError> {
        if s.len() % 2 != 0 {
            return Err(RuleSignatureError::Encode(
                "test signer key contains odd-length hex".to_string(),
            ));
        }
        let mut out = Vec::with_capacity(s.len() / 2);
        for pair in s.as_bytes().chunks_exact(2) {
            let hi = hex_value(pair[0])?;
            let lo = hex_value(pair[1])?;
            out.push((hi << 4) | lo);
        }
        Ok(out)
    }

    fn hex_value(b: u8) -> Result<u8, RuleSignatureError> {
        match b {
            b'0'..=b'9' => Ok(b - b'0'),
            b'a'..=b'f' => Ok(b - b'a' + 10),
            b'A'..=b'F' => Ok(b - b'A' + 10),
            _ => Err(RuleSignatureError::Encode(
                "test signer key contains invalid hex".to_string(),
            )),
        }
    }
}
