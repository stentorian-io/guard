//! Snapshot CBOR codec — v0.2 (SCHEMA_V2).
//!
//! schema_version is the FIRST field of the CBOR map.
//! v0.2 readers REJECT anything other than SCHEMA_V2 (fail-closed). v0.1
//! SCHEMA_V1 const + v1_default() are RETAINED as a compat-test fixture only;
//! production code paths must use SCHEMA_V2 + v2_default().

use crate::allowlist::{AllowlistEntry, MatchType, RuleKind, RuleTier};
use crate::error::Error;
use serde::{Deserialize, Serialize};

pub const SCHEMA_V1: u16 = 1;
pub const SCHEMA_V2: u16 = 2;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Snapshot {
    /// MUST be the first field. Decoder verifies == SCHEMA_V2 (fail-closed otherwise).
    pub schema_version: u16,
    pub generated_at_unix_ms: i64,
    /// Pre-sorted by RuleTier at write time (daemon). The dylib iterates this
    /// Vec linearly and returns at the FIRST matching entry.
    pub entries: Vec<AllowlistEntry>,
    /// Per-`sentinel wrap` snapshot: Some(uuid) for runs/{uuid}.cbor; None for the
    /// daemon-startup snapshot (deprecated post-v0.2 but kept for compat).
    pub run_uuid: Option<String>,
}

impl Snapshot {
    /// v0.1 minimal allowlist — KEPT for backward-compat test fixtures only.
    /// Production code must use v2_default(). decode() rejects this snapshot.
    pub fn v1_default() -> Self {
        Self {
            schema_version: SCHEMA_V1,
            generated_at_unix_ms: 0,
            entries: Vec::new(),
            run_uuid: None,
        }
    }

    /// v0.2 minimal allowlist — used by tests and as the daemon's startup
    /// fallback before any `sentinel wrap` invocation. Real curated content is
    /// loaded from `crates/sentinel-core/data/{allow,deny}/`.
    pub fn v2_default() -> Self {
        Self {
            schema_version: SCHEMA_V2,
            generated_at_unix_ms: 0,
            entries: vec![
                AllowlistEntry {
                    kind: RuleKind::Allow,
                    tier: RuleTier::CuratedAllow,
                    match_type: MatchType::Ip,
                    pattern: "127.0.0.1".into(),
                    reason: "loopback (D-25a)".into(),
                },
                AllowlistEntry {
                    kind: RuleKind::Allow,
                    tier: RuleTier::CuratedAllow,
                    match_type: MatchType::Ip,
                    pattern: "::1".into(),
                    reason: "loopback6 (D-25a)".into(),
                },
                AllowlistEntry {
                    kind: RuleKind::Allow,
                    tier: RuleTier::CuratedAllow,
                    match_type: MatchType::Exact,
                    pattern: "registry.npmjs.org".into(),
                    reason: "npm default registry (ALLOW-01)".into(),
                },
            ],
            run_uuid: None,
        }
    }

    pub fn encode(&self) -> Result<Vec<u8>, Error> {
        let mut buf = Vec::with_capacity(512);
        ciborium::ser::into_writer(self, &mut buf).map_err(|e| Error::Codec(e.to_string()))?;
        Ok(buf)
    }

    /// Decode a snapshot from CBOR bytes. Fails closed on schema version mismatch.
    pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
        let s: Snapshot =
            ciborium::de::from_reader(bytes).map_err(|e| Error::Codec(e.to_string()))?;
        if s.schema_version != SCHEMA_V2 {
            return Err(Error::SchemaVersionMismatch {
                expected: SCHEMA_V2,
                got: s.schema_version,
            });
        }
        Ok(s)
    }
}
