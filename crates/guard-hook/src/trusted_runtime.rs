//! Build-time embedded trusted runtime registry.
//!
//! Entries are SHA-256 content hashes of exact runtime executables from
//! official release artifacts. A match is a structural identity fact about the
//! binary, so it is safe to cache and use before static syscall-byte scanning.

use std::sync::OnceLock;

const TRUSTED_RUNTIME_YAML: &str = include_str!("../../guard-core/data/trusted-runtimes.yaml");

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustedRuntime {
    pub sha256: [u8; 32],
    pub name: String,
    pub version: String,
    pub source: String,
}

#[derive(Debug, Default)]
pub struct TrustedRuntimeRegistry {
    entries: Vec<TrustedRuntime>,
}

impl TrustedRuntimeRegistry {
    pub fn parse(yaml: &str) -> Self {
        let mut entries = Vec::new();
        let mut pending = TrustedRuntimeFields::default();
        for line in yaml.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let field = line.strip_prefix("- ").unwrap_or(line);
            if line.starts_with("- ") && pending.has_any() {
                if let Some(entry) = pending.take_entry() {
                    entries.push(entry);
                }
            }
            if let Some((key, value)) = field.split_once(':') {
                pending.set(key.trim(), yaml_scalar(value.trim()));
            }
        }
        if let Some(entry) = pending.take_entry() {
            entries.push(entry);
        }
        Self { entries }
    }

    pub fn get(&self, sha256: &[u8; 32]) -> Option<&TrustedRuntime> {
        self.entries.iter().find(|entry| &entry.sha256 == sha256)
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

pub fn registry() -> &'static TrustedRuntimeRegistry {
    static REGISTRY: OnceLock<TrustedRuntimeRegistry> = OnceLock::new();
    REGISTRY.get_or_init(|| TrustedRuntimeRegistry::parse(TRUSTED_RUNTIME_YAML))
}

#[derive(Default)]
struct TrustedRuntimeFields {
    sha256: Option<[u8; 32]>,
    name: Option<String>,
    version: Option<String>,
    source: Option<String>,
}

impl TrustedRuntimeFields {
    fn has_any(&self) -> bool {
        self.sha256.is_some()
            || self.name.is_some()
            || self.version.is_some()
            || self.source.is_some()
    }

    fn set(&mut self, key: &str, value: &str) {
        match key {
            "sha256" => self.sha256 = parse_sha256_hex(value),
            "name" => self.name = Some(value.to_string()),
            "version" => self.version = Some(value.to_string()),
            "source" => self.source = Some(value.to_string()),
            _ => {}
        }
    }

    fn take_entry(&mut self) -> Option<TrustedRuntime> {
        let entry = match (
            self.sha256.take(),
            self.name.take(),
            self.version.take(),
            self.source.take(),
        ) {
            (Some(sha256), Some(name), Some(version), Some(source)) => Some(TrustedRuntime {
                sha256,
                name,
                version,
                source,
            }),
            _ => None,
        };
        *self = Self::default();
        entry
    }
}

fn yaml_scalar(value: &str) -> &str {
    value.trim_matches('"').trim_matches('\'')
}

pub fn parse_sha256_hex(hex: &str) -> Option<[u8; 32]> {
    if hex.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, chunk) in hex.as_bytes().chunks_exact(2).enumerate() {
        let hi = hex_nibble(chunk[0])?;
        let lo = hex_nibble(chunk[1])?;
        out[i] = (hi << 4) | lo;
    }
    Some(out)
}

fn hex_nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_valid_entries_and_ignores_comments() {
        let registry = TrustedRuntimeRegistry::parse(
            "\
            runtimes:\n\
              # comment\n\
              - sha256: \"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f\"\n\
                name: node\n\
                version: \"20.0.0\"\n\
                source: https://nodejs.org\n\
              - sha256: not-a-hash\n\
                name: bad\n\
                version: bad\n\
                source: bad\n",
        );
        assert_eq!(registry.len(), 1);
        let hash =
            parse_sha256_hex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
                .unwrap();
        let entry = registry.get(&hash).expect("trusted runtime");
        assert_eq!(entry.name, "node");
        assert_eq!(entry.version, "20.0.0");
    }

    #[test]
    fn sha256_parser_rejects_malformed_values() {
        assert!(parse_sha256_hex("00").is_none());
        assert!(
            parse_sha256_hex("zz0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",)
                .is_none()
        );
    }
}
