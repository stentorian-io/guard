//! Post-quantum rule signing for production persistent policy artifacts.
//!
//! Production signing uses ML-DSA-65 so first-release project-owned signatures
//! are post-quantum from the start. macOS does not currently provide
//! Secure Enclave ML-DSA keys, so the private key is stored as a user-owned
//! 0600 file and never copied into daemon-writable state.

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::Command;

use guard_core::{
    ManagementActionPayloadV1, RULE_SIGNATURE_SCHEME_ML_DSA_65_SHA256, RuleSignaturePayloadV1,
    RuleSignatureV1, SIGNER_KIND_SOFTWARE_ML_DSA, SnapshotSignaturePayloadV1, SnapshotSignatureV1,
    canonical_management_action_payload_bytes, canonical_rule_payload_bytes,
    canonical_snapshot_payload_bytes, sha256_hex,
};
use pqcrypto_mldsa::mldsa65;
use pqcrypto_traits::sign::{DetachedSignature as _, PublicKey as _, SecretKey as _};

use crate::CliError;

const PRIVATE_KEY_FILENAME: &str = "ml-dsa-65-rule-signing-key";
const DISABLE_PQ_SIGNER_ENV: &str = "STT_GUARD_DISABLE_PQ_SIGNER";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PqSignerEnrollment {
    pub signer_kind: String,
    pub public_key_x963: Vec<u8>,
    pub public_key_sha256: String,
    pub label: String,
}

struct PqSigningKey {
    public_key: mldsa65::PublicKey,
    secret_key: mldsa65::SecretKey,
}

pub fn enroll_pq_signer_for_init() -> Result<PqSignerEnrollment, CliError> {
    if pq_signer_disabled() {
        return Err(unavailable_error());
    }

    let key_path = init_user_key_path()?;
    let signing_key = load_or_create_signing_key(&key_path)?;
    repair_init_user_ownership(&key_path)?;

    let public_key_x963 = signing_key.public_key.as_bytes().to_vec();
    Ok(PqSignerEnrollment {
        signer_kind: SIGNER_KIND_SOFTWARE_ML_DSA.to_string(),
        public_key_sha256: sha256_hex(&public_key_x963),
        public_key_x963,
        label: init_user_label(),
    })
}

pub fn sign_rule_payload(payload: &RuleSignaturePayloadV1) -> Result<RuleSignatureV1, CliError> {
    let payload_bytes = canonical_rule_payload_bytes(payload)
        .map_err(|e| CliError::Other(format!("canonical rule payload encode failed: {e}")))?;
    let signing_key = load_current_user_signing_key()?;
    Ok(rule_signature_from_payload(
        &payload_bytes,
        payload.created_at_unix_ms,
        &signing_key,
    ))
}

pub fn sign_snapshot_payload(
    payload: &SnapshotSignaturePayloadV1,
) -> Result<SnapshotSignatureV1, CliError> {
    let payload_bytes = canonical_snapshot_payload_bytes(payload)
        .map_err(|e| CliError::Other(format!("canonical snapshot payload encode failed: {e}")))?;
    let signing_key = load_current_user_signing_key()?;
    let signature = mldsa65::detached_sign(&payload_bytes, &signing_key.secret_key);
    let public_key_x963 = signing_key.public_key.as_bytes().to_vec();

    Ok(SnapshotSignatureV1 {
        scheme: RULE_SIGNATURE_SCHEME_ML_DSA_65_SHA256.to_string(),
        signer_kind: SIGNER_KIND_SOFTWARE_ML_DSA.to_string(),
        public_key_sha256: sha256_hex(&public_key_x963),
        public_key_x963,
        signature_der: signature.as_bytes().to_vec(),
        signed_payload_sha256: sha256_hex(&payload_bytes),
        signature_created_at_unix_ms: payload.generated_at_unix_ms,
    })
}

pub fn sign_management_action_payload(
    payload: &ManagementActionPayloadV1,
) -> Result<RuleSignatureV1, CliError> {
    let payload_bytes = canonical_management_action_payload_bytes(payload).map_err(|e| {
        CliError::Other(format!(
            "canonical management-action payload encode failed: {e}"
        ))
    })?;
    let signing_key = load_current_user_signing_key()?;
    Ok(rule_signature_from_payload(
        &payload_bytes,
        payload.created_at_unix_ms,
        &signing_key,
    ))
}

fn rule_signature_from_payload(
    payload_bytes: &[u8],
    created_at_unix_ms: i64,
    signing_key: &PqSigningKey,
) -> RuleSignatureV1 {
    let signature = mldsa65::detached_sign(payload_bytes, &signing_key.secret_key);
    let public_key_x963 = signing_key.public_key.as_bytes().to_vec();

    RuleSignatureV1 {
        scheme: RULE_SIGNATURE_SCHEME_ML_DSA_65_SHA256.to_string(),
        signer_kind: SIGNER_KIND_SOFTWARE_ML_DSA.to_string(),
        public_key_sha256: sha256_hex(&public_key_x963),
        public_key_x963,
        signature_der: signature.as_bytes().to_vec(),
        signed_payload_sha256: sha256_hex(payload_bytes),
        signature_created_at_unix_ms: created_at_unix_ms,
    }
}

fn load_current_user_signing_key() -> Result<PqSigningKey, CliError> {
    if pq_signer_disabled() {
        return Err(unavailable_error());
    }
    load_signing_key(&current_user_key_path()?)
}

fn load_or_create_signing_key(path: &Path) -> Result<PqSigningKey, CliError> {
    match load_signing_key(path) {
        Ok(signing_key) => Ok(signing_key),
        Err(_) if !path.exists() => create_signing_key(path),
        Err(err) => Err(err),
    }
}

fn create_signing_key(path: &Path) -> Result<PqSigningKey, CliError> {
    let parent = path
        .parent()
        .ok_or_else(|| CliError::Other(format!("invalid signing key path: {}", path.display())))?;
    fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(parent)
        .map_err(|e| CliError::Other(format!("create signing key directory: {e}")))?;
    fs::set_permissions(parent, fs::Permissions::from_mode(0o700))
        .map_err(|e| CliError::Other(format!("chmod signing key directory: {e}")))?;

    let (public_key, secret_key) = mldsa65::keypair();
    let content = signing_key_file_content(&public_key, &secret_key);
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .map_err(|e| CliError::Other(format!("create signing key {}: {e}", path.display())))?;
    file.write_all(content.as_bytes())
        .map_err(|e| CliError::Other(format!("write signing key {}: {e}", path.display())))?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))
        .map_err(|e| CliError::Other(format!("chmod signing key {}: {e}", path.display())))?;

    Ok(PqSigningKey {
        public_key,
        secret_key,
    })
}

fn load_signing_key(path: &Path) -> Result<PqSigningKey, CliError> {
    let content = fs::read_to_string(path)
        .map_err(|e| CliError::Other(format!("read signing key {}: {e}", path.display())))?;
    let scheme = parse_field(&content, "scheme")?;
    if scheme != RULE_SIGNATURE_SCHEME_ML_DSA_65_SHA256 {
        return Err(CliError::Other(format!(
            "unsupported signing key scheme in {}: {scheme}",
            path.display()
        )));
    }
    let public_key =
        mldsa65::PublicKey::from_bytes(&decode_hex(parse_field(&content, "public_key_hex")?)?)
            .map_err(|e| CliError::Other(format!("decode ML-DSA public key: {e:?}")))?;
    let secret_key =
        mldsa65::SecretKey::from_bytes(&decode_hex(parse_field(&content, "secret_key_hex")?)?)
            .map_err(|e| CliError::Other(format!("decode ML-DSA secret key: {e:?}")))?;

    Ok(PqSigningKey {
        public_key,
        secret_key,
    })
}

fn signing_key_file_content(
    public_key: &mldsa65::PublicKey,
    secret_key: &mldsa65::SecretKey,
) -> String {
    format!(
        "scheme={}\npublic_key_hex={}\nsecret_key_hex={}\n",
        RULE_SIGNATURE_SCHEME_ML_DSA_65_SHA256,
        hex_lower(public_key.as_bytes()),
        hex_lower(secret_key.as_bytes())
    )
}

fn current_user_key_path() -> Result<PathBuf, CliError> {
    let home = std::env::var_os("HOME")
        .map(PathBuf::from)
        .ok_or_else(|| CliError::Other("HOME environment variable must be set".into()))?;
    Ok(home
        .join("Library/Application Support/Stentorian Guard")
        .join(PRIVATE_KEY_FILENAME))
}

fn init_user_key_path() -> Result<PathBuf, CliError> {
    if unsafe { libc::geteuid() } != 0 {
        return current_user_key_path();
    }

    let user = init_user()?;
    Ok(home_for_user(&user)?
        .join("Library/Application Support/Stentorian Guard")
        .join(PRIVATE_KEY_FILENAME))
}

fn init_user() -> Result<String, CliError> {
    std::env::var("SUDO_USER")
        .ok()
        .filter(|user| user != "root")
        .ok_or_else(|| {
            CliError::Other(
                "ML-DSA signer enrollment requires running init via sudo from the target user \
                 (for example: sudo stt-guard init); refusing to enroll a root-owned signing key"
                    .into(),
            )
        })
}

fn home_for_user(user: &str) -> Result<PathBuf, CliError> {
    let output = Command::new("/usr/bin/dscl")
        .args([".", "-read", &format!("/Users/{user}"), "NFSHomeDirectory"])
        .output()
        .map_err(|e| CliError::Other(format!("lookup home for {user}: {e}")))?;
    if !output.status.success() {
        return Err(CliError::Other(format!("lookup home for {user} failed")));
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    let Some((_, home)) = stdout.trim().split_once(": ") else {
        return Err(CliError::Other(format!(
            "home lookup for {user} did not include NFSHomeDirectory"
        )));
    };
    Ok(PathBuf::from(home))
}

fn repair_init_user_ownership(path: &Path) -> Result<(), CliError> {
    if unsafe { libc::geteuid() } != 0 {
        return Ok(());
    }

    let user = init_user()?;
    let parent = path
        .parent()
        .ok_or_else(|| CliError::Other(format!("invalid signing key path: {}", path.display())))?;
    run_cmd(
        "/usr/sbin/chown",
        &["-R", &user, &parent.to_string_lossy()],
        "set ML-DSA signer ownership",
    )?;
    run_cmd(
        "/bin/chmod",
        &["700", &parent.to_string_lossy()],
        "set ML-DSA signer directory permissions",
    )?;
    run_cmd(
        "/bin/chmod",
        &["600", &path.to_string_lossy()],
        "set ML-DSA signer key permissions",
    )
}

fn run_cmd(program: &str, args: &[&str], context: &str) -> Result<(), CliError> {
    let status = Command::new(program)
        .args(args)
        .status()
        .map_err(|e| CliError::Other(format!("{context}: {e}")))?;
    if status.success() {
        Ok(())
    } else {
        Err(CliError::Other(format!("{context}: {status}")))
    }
}

fn init_user_label() -> String {
    if unsafe { libc::geteuid() } == 0 {
        if let Ok(user) = init_user() {
            return format!("ML-DSA-65 software signer ({user})");
        }
    }
    "ML-DSA-65 software signer".to_string()
}

fn pq_signer_disabled() -> bool {
    std::env::var_os(DISABLE_PQ_SIGNER_ENV).is_some()
}

fn unavailable_error() -> CliError {
    CliError::Other("ML-DSA signing key unavailable; run sudo stt-guard init".into())
}

fn parse_field<'a>(content: &'a str, key: &str) -> Result<&'a str, CliError> {
    let prefix = format!("{key}=");
    content
        .lines()
        .find_map(|line| line.strip_prefix(&prefix))
        .ok_or_else(|| CliError::Other(format!("signing key omitted {key}")))
}

fn decode_hex(s: &str) -> Result<Vec<u8>, CliError> {
    if s.len() % 2 != 0 {
        return Err(CliError::Other(
            "signing key contains odd-length hex".into(),
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

fn hex_value(b: u8) -> Result<u8, CliError> {
    match b {
        b'0'..=b'9' => Ok(b - b'0'),
        b'a'..=b'f' => Ok(b - b'a' + 10),
        b'A'..=b'F' => Ok(b - b'A' + 10),
        _ => Err(CliError::Other("signing key contains invalid hex".into())),
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
