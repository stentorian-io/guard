//! Snapshot CBOR codec.
//!
//! schema_version is the FIRST field per .planning/phases/01-foundations-hook-hello-world/01-RESEARCH.md
//! line 547. Phase 1 writes SCHEMA_V1; readers refuse anything else (fail-closed).

use crate::allowlist::AllowlistEntry;
use crate::error::Error;
use serde::{Deserialize, Serialize};

/// Current schema version. Bump in Phase 2 forces co-shipping of daemon + dylib.
pub const SCHEMA_V1: u16 = 1;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Snapshot {
    /// MUST be the first field. Decoder verifies == SCHEMA_V1 (fail-closed otherwise).
    pub schema_version: u16,
    pub generated_at_unix_ms: i64,
    pub entries: Vec<AllowlistEntry>,
}

impl Snapshot {
    /// Phase 1 minimal allowlist (D-18): loopback + registry.npmjs.org + test marker.
    pub fn phase1_default() -> Self {
        Self {
            schema_version: SCHEMA_V1,
            generated_at_unix_ms: 0,
            entries: vec![
                AllowlistEntry::Ip("127.0.0.1".to_string()),
                AllowlistEntry::Ip("::1".to_string()),
                AllowlistEntry::Exact("localhost".to_string()),
                AllowlistEntry::Exact("registry.npmjs.org".to_string()),
                // Internal test marker — used by sentinel-e2e to validate the matcher
                // path without depending on real registry availability.
                AllowlistEntry::Exact("sentinel-test-marker.invalid".to_string()),
            ],
        }
    }

    /// Encode this snapshot to CBOR bytes.
    pub fn encode(&self) -> Result<Vec<u8>, Error> {
        let mut buf = Vec::with_capacity(256);
        ciborium::ser::into_writer(self, &mut buf)
            .map_err(|e| Error::Codec(e.to_string()))?;
        Ok(buf)
    }

    /// Decode a snapshot from CBOR bytes. Fails closed on schema version mismatch.
    pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
        let s: Snapshot = ciborium::de::from_reader(bytes)
            .map_err(|e| Error::Codec(e.to_string()))?;
        if s.schema_version != SCHEMA_V1 {
            return Err(Error::SchemaVersionMismatch {
                expected: SCHEMA_V1,
                got: s.schema_version,
            });
        }
        Ok(s)
    }
}
