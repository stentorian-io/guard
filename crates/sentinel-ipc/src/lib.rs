//! Sentinel IPC: length-prefixed CBOR framing + Unix socket transport with
//! macOS-native peer audit-token authentication.
//!
//! Phase 1 protocol: a single request-reply (CLI sends RegisterRoot; daemon
//! sends Reply::Ack or Reply::Err).
//!
//! Phase 2 adds new message types under IPC_SCHEMA_V2 — RegisterRoot/Reply
//! are FROZEN at IPC_SCHEMA_V1 (D-30 contract preservation).

pub mod error;
pub mod frame;
pub mod messages;
pub mod transport;

pub use error::IpcError;
pub use messages::{
    // Phase 1 (FROZEN)
    AuditTokenWire,
    // Phase 2
    DylibLoaded,
    DylibLoadedAck,
    ExecAck,
    ExecEvent,
    ForkAck,
    ForkEvent,
    IPC_SCHEMA_V1,
    IPC_SCHEMA_V2,
    PrepareSnapshot,
    RegisterRoot,
    Reply,
    Resolve,
    ResolveReply,
    SOCKADDR_WIRE_LEN,
    SnapshotReply,
    TrustPolicy,
    TrustPolicyReply,
};
