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
    /// Phase 1 minimal allowlist — RETAINED for backward-compat test fixtures only.
    /// Phase 2 production code uses `phase2_default()` (added in Task 2). Entries
    /// are empty here because the V1 enum (Exact|Suffix|Ip variants) was replaced
    /// by the V2 struct in Task 1; this default still produces SCHEMA_V1 so the
    /// version-mismatch test path can exercise it.
    pub fn phase1_default() -> Self {
        Self {
            schema_version: SCHEMA_V1,
            generated_at_unix_ms: 0,
            entries: Vec::new(),
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
