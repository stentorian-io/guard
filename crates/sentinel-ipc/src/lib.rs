//! Sentinel IPC: length-prefixed CBOR framing + Unix socket transport with
//! macOS-native peer audit-token authentication.
//!
//! Phase 1 protocol: a single request-reply (CLI sends RegisterRoot; daemon
//! sends Reply::Ack or Reply::Err).

pub mod error;
pub mod frame;
pub mod messages;
pub mod transport;

pub use error::IpcError;
pub use messages::{AuditTokenWire, IPC_SCHEMA_V1, RegisterRoot, Reply};
