//! Hardware-backed rule signing for production persistent user rules.
//!
//! macOS production support uses a non-exportable Secure Enclave P-256 key in
//! the invoking user's keychain. `stt-guard init` enrolls/locates that key and
//! registers the public half with the daemon's trusted signer registry. Later
//! rule approvals sign the canonical rule payload with the private key; the
//! daemon can verify but cannot forge those signatures.

use std::process::Command;

use guard_core::{
    RULE_SIGNATURE_SCHEME_ECDSA_P256_SHA256, RuleSignaturePayloadV1, RuleSignatureV1,
    SIGNER_KIND_SECURE_ENCLAVE, SnapshotSignaturePayloadV1, SnapshotSignatureV1,
    canonical_rule_payload_bytes, canonical_snapshot_payload_bytes, sha256_hex,
};

use crate::CliError;

const KEY_TAG: &str = "com.stentorian-guard.rule-signing.v1";
const DISABLE_HARDWARE_SIGNER_ENV: &str = "STT_GUARD_DISABLE_HARDWARE_SIGNER";

const SECURE_ENCLAVE_SWIFT: &str = r#"
import Foundation
import Security

let tag = Data(CommandLine.arguments[2].utf8)
let prompt = "Stentorian Guard needs your hardware-backed rule-signing key."

func fail(_ message: String) -> Never {
    FileHandle.standardError.write(Data((message + "\n").utf8))
    exit(1)
}

func hex(_ data: Data) -> String {
    data.map { String(format: "%02x", $0) }.joined()
}

func dataFromHex(_ s: String) -> Data? {
    if s.count % 2 != 0 { return nil }
    var out = Data(capacity: s.count / 2)
    var i = s.startIndex
    while i < s.endIndex {
        let j = s.index(i, offsetBy: 2)
        guard let b = UInt8(s[i..<j], radix: 16) else { return nil }
        out.append(b)
        i = j
    }
    return out
}

func findPrivateKey() -> SecKey? {
    let query: [String: Any] = [
        kSecClass as String: kSecClassKey,
        kSecAttrApplicationTag as String: tag,
        kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
        kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
        kSecReturnRef as String: true,
        kSecUseOperationPrompt as String: prompt
    ]
    var item: CFTypeRef?
    let status = SecItemCopyMatching(query as CFDictionary, &item)
    if status == errSecSuccess {
        return (item as! SecKey)
    }
    return nil
}

func publicKeyHex(_ privateKey: SecKey) -> String {
    guard let pub = SecKeyCopyPublicKey(privateKey) else {
        fail("Secure Enclave key has no public key")
    }
    var error: Unmanaged<CFError>?
    guard let data = SecKeyCopyExternalRepresentation(pub, &error) as Data? else {
        fail("export Secure Enclave public key failed: \(String(describing: error))")
    }
    return hex(data)
}

func enroll() {
    if let existing = findPrivateKey() {
        print("public_key_x963_hex=\(publicKeyHex(existing))")
        return
    }

    var acError: Unmanaged<CFError>?
    guard let access = SecAccessControlCreateWithFlags(
        nil,
        kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
        [.privateKeyUsage, .userPresence],
        &acError
    ) else {
        fail("create Secure Enclave access control failed: \(String(describing: acError))")
    }

    let attrs: [String: Any] = [
        kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
        kSecAttrKeySizeInBits as String: 256,
        kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
        kSecPrivateKeyAttrs as String: [
            kSecAttrIsPermanent as String: true,
            kSecAttrApplicationTag as String: tag,
            kSecAttrAccessControl as String: access
        ]
    ]

    var error: Unmanaged<CFError>?
    guard let key = SecKeyCreateRandomKey(attrs as CFDictionary, &error) else {
        fail("create Secure Enclave signing key failed: \(String(describing: error))")
    }
    print("public_key_x963_hex=\(publicKeyHex(key))")
}

func sign(_ payloadHex: String) {
    guard let key = findPrivateKey() else {
        fail("hardware-backed signing key unavailable; run sudo stt-guard init to enroll Secure Enclave signing")
    }
    guard let payload = dataFromHex(payloadHex) else {
        fail("invalid payload hex")
    }
    let algorithm = SecKeyAlgorithm.ecdsaSignatureMessageX962SHA256
    guard SecKeyIsAlgorithmSupported(key, .sign, algorithm) else {
        fail("Secure Enclave key does not support ECDSA P-256 SHA-256 signing")
    }
    var error: Unmanaged<CFError>?
    guard let signature = SecKeyCreateSignature(key, algorithm, payload as CFData, &error) as Data? else {
        fail("Secure Enclave signing failed: \(String(describing: error))")
    }
    print("public_key_x963_hex=\(publicKeyHex(key))")
    print("signature_der_hex=\(hex(signature))")
}

if CommandLine.arguments.count < 3 {
    fail("usage: swift -e <script> enroll|sign <tag> [payload_hex]")
}

switch CommandLine.arguments[1] {
case "enroll":
    enroll()
case "sign":
    if CommandLine.arguments.count != 4 { fail("sign requires payload_hex") }
    sign(CommandLine.arguments[3])
default:
    fail("unknown mode")
}
"#;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HardwareSignerEnrollment {
    pub signer_kind: String,
    pub public_key_x963: Vec<u8>,
    pub public_key_sha256: String,
    pub label: String,
}

pub fn enroll_secure_enclave_for_init() -> Result<HardwareSignerEnrollment, CliError> {
    if hardware_signer_disabled() {
        return Err(unavailable_error());
    }
    let output = run_swift_as_init_user("enroll", None)?;
    let public_key_x963 = parse_hex_field(&output, "public_key_x963_hex")?;
    let public_key_sha256 = sha256_hex(&public_key_x963);
    Ok(HardwareSignerEnrollment {
        signer_kind: SIGNER_KIND_SECURE_ENCLAVE.to_string(),
        public_key_x963,
        public_key_sha256,
        label: init_user_label(),
    })
}

pub fn sign_rule_payload(payload: &RuleSignaturePayloadV1) -> Result<RuleSignatureV1, CliError> {
    if hardware_signer_disabled() {
        return Err(unavailable_error());
    }
    let payload_bytes = canonical_rule_payload_bytes(payload)
        .map_err(|e| CliError::Other(format!("canonical rule payload encode failed: {e}")))?;
    let output = run_swift_current_user("sign", Some(&hex_lower(&payload_bytes)))?;
    let public_key_x963 = parse_hex_field(&output, "public_key_x963_hex")?;
    let signature_der = parse_hex_field(&output, "signature_der_hex")?;
    Ok(RuleSignatureV1 {
        scheme: RULE_SIGNATURE_SCHEME_ECDSA_P256_SHA256.to_string(),
        signer_kind: SIGNER_KIND_SECURE_ENCLAVE.to_string(),
        public_key_sha256: sha256_hex(&public_key_x963),
        public_key_x963,
        signature_der,
        signed_payload_sha256: sha256_hex(&payload_bytes),
        signature_created_at_unix_ms: payload.created_at_unix_ms,
    })
}

pub fn sign_snapshot_payload(
    payload: &SnapshotSignaturePayloadV1,
) -> Result<SnapshotSignatureV1, CliError> {
    if hardware_signer_disabled() {
        return Err(unavailable_error());
    }
    let payload_bytes = canonical_snapshot_payload_bytes(payload)
        .map_err(|e| CliError::Other(format!("canonical snapshot payload encode failed: {e}")))?;
    let output = run_swift_current_user("sign", Some(&hex_lower(&payload_bytes)))?;
    let public_key_x963 = parse_hex_field(&output, "public_key_x963_hex")?;
    let signature_der = parse_hex_field(&output, "signature_der_hex")?;
    Ok(SnapshotSignatureV1 {
        scheme: RULE_SIGNATURE_SCHEME_ECDSA_P256_SHA256.to_string(),
        signer_kind: SIGNER_KIND_SECURE_ENCLAVE.to_string(),
        public_key_sha256: sha256_hex(&public_key_x963),
        public_key_x963,
        signature_der,
        signed_payload_sha256: sha256_hex(&payload_bytes),
        signature_created_at_unix_ms: payload.generated_at_unix_ms,
    })
}

fn hardware_signer_disabled() -> bool {
    std::env::var_os(DISABLE_HARDWARE_SIGNER_ENV).is_some()
}

fn unavailable_error() -> CliError {
    CliError::Other(
        "hardware-backed signing key unavailable; software-only rule signing is unsupported".into(),
    )
}

fn run_swift_current_user(mode: &str, payload_hex: Option<&str>) -> Result<String, CliError> {
    run_swift_command(CommandSpec::CurrentUser, mode, payload_hex)
}

fn run_swift_as_init_user(mode: &str, payload_hex: Option<&str>) -> Result<String, CliError> {
    run_swift_command(CommandSpec::InitInvokingUser, mode, payload_hex)
}

enum CommandSpec {
    CurrentUser,
    InitInvokingUser,
}

fn run_swift_command(
    command_spec: CommandSpec,
    mode: &str,
    payload_hex: Option<&str>,
) -> Result<String, CliError> {
    let swift = "/usr/bin/swift";
    if !std::path::Path::new(swift).exists() {
        return Err(unavailable_error());
    }

    let mut command = match command_spec {
        CommandSpec::CurrentUser => Command::new(swift),
        CommandSpec::InitInvokingUser => init_user_swift_command(swift)?,
    };
    command
        .arg("-e")
        .arg(SECURE_ENCLAVE_SWIFT)
        .arg(mode)
        .arg(KEY_TAG);
    if let Some(payload_hex) = payload_hex {
        command.arg(payload_hex);
    }

    let output = command
        .output()
        .map_err(|e| CliError::Other(format!("launch hardware signer helper: {e}")))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        if stderr.is_empty() {
            return Err(unavailable_error());
        }
        return Err(CliError::Other(stderr));
    }
    String::from_utf8(output.stdout).map_err(|e| {
        CliError::Other(format!(
            "hardware signer helper emitted non-UTF8 output: {e}"
        ))
    })
}

fn init_user_swift_command(swift: &str) -> Result<Command, CliError> {
    if unsafe { libc::geteuid() } != 0 {
        return Ok(Command::new(swift));
    }

    let sudo_user = std::env::var("SUDO_USER").ok().filter(|u| u != "root");
    let Some(user) = sudo_user else {
        return Err(CliError::Other(
            "hardware signer enrollment requires running init via sudo from the target user \
             (for example: sudo stt-guard init); refusing to enroll a root-owned signing key"
                .into(),
        ));
    };

    let mut command = Command::new("/usr/bin/sudo");
    command.arg("-u").arg(user).arg(swift);
    Ok(command)
}

fn init_user_label() -> String {
    if unsafe { libc::geteuid() } == 0 {
        if let Ok(user) = std::env::var("SUDO_USER") {
            if user != "root" {
                return format!("macOS Secure Enclave ({user})");
            }
        }
    }
    "macOS Secure Enclave".to_string()
}

fn parse_hex_field(output: &str, key: &str) -> Result<Vec<u8>, CliError> {
    let prefix = format!("{key}=");
    let value = output
        .lines()
        .find_map(|line| line.strip_prefix(&prefix))
        .ok_or_else(|| CliError::Other(format!("hardware signer helper omitted {key}")))?;
    decode_hex(value)
}

fn decode_hex(s: &str) -> Result<Vec<u8>, CliError> {
    if s.len() % 2 != 0 {
        return Err(CliError::Other(
            "hardware signer helper emitted odd-length hex".into(),
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
        _ => Err(CliError::Other(
            "hardware signer helper emitted invalid hex".into(),
        )),
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decode_hex_accepts_lower_and_upper() {
        assert_eq!(decode_hex("0001feFF").unwrap(), vec![0, 1, 254, 255]);
    }

    #[test]
    fn decode_hex_rejects_invalid_input() {
        assert!(decode_hex("0").is_err());
        assert!(decode_hex("zz").is_err());
    }

    #[test]
    fn parse_hex_field_reads_named_line() {
        let parsed =
            parse_hex_field("noise\npublic_key_x963_hex=000102\n", "public_key_x963_hex").unwrap();
        assert_eq!(parsed, vec![0, 1, 2]);
    }
}
