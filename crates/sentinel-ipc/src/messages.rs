//! Wire types for the CLI ↔ daemon protocol.

use serde::{Deserialize, Serialize};

pub const IPC_SCHEMA_V1: u16 = 1;

/// Wire-shape mirror of `sentinel_core::AuditToken`. Defined here (rather than
/// re-using sentinel-core's) so that wire-vs-domain conversions are explicit
/// and there's a single decoded representation per layer.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[repr(C)]
pub struct AuditTokenWire {
    pub val: [u32; 8],
}

impl From<sentinel_core::AuditToken> for AuditTokenWire {
    fn from(t: sentinel_core::AuditToken) -> Self {
        Self { val: t.val }
    }
}

impl From<AuditTokenWire> for sentinel_core::AuditToken {
    fn from(w: AuditTokenWire) -> Self {
        sentinel_core::AuditToken { val: w.val }
    }
}

/// CLI → daemon: the spawned wrapped process's audit token, sent immediately
/// after spawn so the daemon records it as a tracked-root before the wrapped
/// process makes any outbound calls.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct RegisterRoot {
    pub schema_version: u16,        // FIRST field — must equal IPC_SCHEMA_V1
    pub audit_token: AuditTokenWire,
}

impl RegisterRoot {
    pub fn new(token: sentinel_core::AuditToken) -> Self {
        Self {
            schema_version: IPC_SCHEMA_V1,
            audit_token: AuditTokenWire::from(token),
        }
    }
}

/// Daemon → CLI: response to RegisterRoot.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum Reply {
    Ack { schema_version: u16 },
    Err { schema_version: u16, message: String },
}

impl Reply {
    pub fn ack() -> Self {
        Reply::Ack { schema_version: IPC_SCHEMA_V1 }
    }

    pub fn err(m: impl Into<String>) -> Self {
        Reply::Err { schema_version: IPC_SCHEMA_V1, message: m.into() }
    }

    pub fn schema(&self) -> u16 {
        match self {
            Reply::Ack { schema_version } | Reply::Err { schema_version, .. } => *schema_version,
        }
    }
}
