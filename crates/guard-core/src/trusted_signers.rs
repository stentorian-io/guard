//! Trusted signer manifest parsing.
//!
//! The production trust root is a root-owned TSV manifest outside daemon-writable
//! state. Filesystem ownership checks stay with the caller; this module only
//! parses and matches manifest contents consistently across daemon and hook.

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TrustedSigner {
    pub public_key_sha256: String,
    pub signer_kind: String,
    pub public_key_x963_hex: String,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum TrustedSignerManifestError {
    #[error("trusted signer manifest contains odd-length public key hex")]
    OddLengthPublicKeyHex,
    #[error("trusted signer manifest contains invalid public key hex")]
    InvalidPublicKeyHex,
}

pub fn parse_trusted_signers(
    contents: &str,
) -> Result<Vec<TrustedSigner>, TrustedSignerManifestError> {
    let mut signers = Vec::new();
    for line in contents.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut parts = line.split('\t');
        let Some(public_key_sha256) = parts.next() else {
            continue;
        };
        let Some(signer_kind) = parts.next() else {
            continue;
        };
        let Some(public_key_x963_hex) = parts.next() else {
            continue;
        };
        decode_hex(public_key_x963_hex)?;
        signers.push(TrustedSigner {
            public_key_sha256: public_key_sha256.to_string(),
            signer_kind: signer_kind.to_string(),
            public_key_x963_hex: public_key_x963_hex.to_ascii_lowercase(),
        });
    }
    Ok(signers)
}

pub fn first_trusted_signer(
    contents: &str,
) -> Result<Option<TrustedSigner>, TrustedSignerManifestError> {
    Ok(parse_trusted_signers(contents)?.into_iter().next())
}

pub fn trusted_signer_matches(
    contents: &str,
    public_key_sha256: &str,
    signer_kind: &str,
    public_key_x963: Option<&[u8]>,
) -> Result<bool, TrustedSignerManifestError> {
    let expected_key_hex = public_key_x963.map(hex_lower);
    Ok(parse_trusted_signers(contents)?.into_iter().any(|signer| {
        signer.public_key_sha256 == public_key_sha256
            && signer.signer_kind == signer_kind
            && expected_key_hex
                .as_deref()
                .map(|expected| expected == signer.public_key_x963_hex)
                .unwrap_or(true)
    }))
}

pub fn decode_hex(s: &str) -> Result<Vec<u8>, TrustedSignerManifestError> {
    if s.len() % 2 != 0 {
        return Err(TrustedSignerManifestError::OddLengthPublicKeyHex);
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    for pair in s.as_bytes().chunks_exact(2) {
        let hi = hex_value(pair[0])?;
        let lo = hex_value(pair[1])?;
        out.push((hi << 4) | lo);
    }
    Ok(out)
}

fn hex_value(b: u8) -> Result<u8, TrustedSignerManifestError> {
    match b {
        b'0'..=b'9' => Ok(b - b'0'),
        b'a'..=b'f' => Ok(b - b'a' + 10),
        b'A'..=b'F' => Ok(b - b'A' + 10),
        _ => Err(TrustedSignerManifestError::InvalidPublicKeyHex),
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
    fn parses_comments_blank_lines_and_entries() {
        let entries =
            parse_trusted_signers("# c\n\nabc\tsecure-enclave\t0001ff\tlabel\n").expect("parse");
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].public_key_sha256, "abc");
        assert_eq!(entries[0].signer_kind, "secure-enclave");
        assert_eq!(entries[0].public_key_x963_hex, "0001ff");
    }

    #[test]
    fn matches_fingerprint_kind_and_public_key() {
        let contents = "abc\tsecure-enclave\t0001ff\tlabel\n";
        assert!(
            trusted_signer_matches(contents, "abc", "secure-enclave", Some(&[0, 1, 255]))
                .expect("match")
        );
        assert!(
            !trusted_signer_matches(contents, "abc", "secure-enclave", Some(&[0, 1, 254]))
                .expect("mismatch")
        );
        assert!(
            !trusted_signer_matches(contents, "abc", "tpm", Some(&[0, 1, 255]))
                .expect("kind mismatch")
        );
    }

    #[test]
    fn rejects_malformed_public_key_hex() {
        assert_eq!(
            parse_trusted_signers("abc\tsecure-enclave\t0\n").unwrap_err(),
            TrustedSignerManifestError::OddLengthPublicKeyHex
        );
        assert_eq!(
            parse_trusted_signers("abc\tsecure-enclave\tzz\n").unwrap_err(),
            TrustedSignerManifestError::InvalidPublicKeyHex
        );
    }
}
