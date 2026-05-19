//! Sentinel IPC: length-prefixed CBOR framing + Unix socket transport with
//! macOS-native peer audit-token authentication.
//!
//! v0.1 protocol: a single request-reply (CLI sends RegisterRoot; daemon
//! sends Reply::Ack or Reply::Err).
//!
//! v0.2 adds new message types under IPC_SCHEMA_V2 — RegisterRoot/Reply
//! are FROZEN at IPC_SCHEMA_V1.

pub mod error;
pub mod frame;
pub mod messages;
pub mod transport;

pub use error::IpcError;
pub use messages::{
    // v0.1 (FROZEN)
    AuditTokenWire,
    // v0.2
    DylibLoaded,
    DylibLoadedAck,
    EnvNotPropagatedGap,
    EnvNotPropagatedGapAck,
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
    // v0.3
    IPC_SCHEMA_V3,
    // v0.3 — Status (tag 0x09)
    DaemonStateKind,
    FeedInfo,
    GapInfo,
    InstallArtifact,
    InstallInfo,
    Status,
    StatusCounters,
    StatusReply,
    TrackedRootInfo,
    // v0.3 — Prompt channel (tag 0x0A)
    PromptChannelInit,
    PromptChannelInitAck,
    // v0.3 — Prompt request/response/cancel (channel-internal)
    PackageContext,
    ProcessCtx,
    PromptCancel,
    PromptRequest,
    PromptResponse,
    PromptVerdict,
    RulePattern,
    SuggestedRule,
    // v0.3 — InsertUserRule (tag 0x0B)
    InsertUserRule,
    InsertUserRuleReply,
    // v0.3 — ReadInstallArtifacts (tag 0x0C)
    ReadInstallArtifacts,
    ReadInstallArtifactsReply,
    // v0.3 — BaselineCommit (tag 0x0D)
    BaselineCommit,
    BaselineCommitReply,
    ProposedRule,
    // v0.4 — Threat-intel and SnapshotReply::Ok V4 schema bump
    IPC_SCHEMA_V4,
    IntelMatch,
    FeedWarning,
    // v0.7 — ListRules (tag 0x0E)
    ListRules,
    ListRulesReply,
    RuleRow,
    // v0.7 — DeleteInstallArtifacts (tag 0x11)
    DeleteInstallArtifacts,
    DeleteInstallArtifactsReply,
    // v0.3 — DenyNotify (tag 0x12)
    DenyNotify,
    DenyNotifyAck,
    // v0.4 — ExecBlocked (tag 0x13)
    ExecBlocked,
    ExecBlockedAck,
    // v0.4 — PersistenceWrite (tag 0x14)
    PersistenceWrite,
    PersistenceWriteAck,
    // v0.5 — Ping (tag 0x15; watchdog liveness)
    Ping,
    PingReply,
};
