//! Stentorian Guard IPC: length-prefixed CBOR framing + Unix socket transport with
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
pub mod signed_frame;
pub mod transport;

pub use error::IpcError;
pub use messages::{
    // v0.1 (FROZEN)
    AuditTokenWire,
    // v0.3 — BaselineCommit (tag 0x0D)
    BaselineCommit,
    BaselineCommitReply,
    // v0.3 — Status (tag 0x09)
    DaemonStateKind,
    // v0.7 — DeleteInstallArtifacts (tag 0x11)
    DeleteInstallArtifacts,
    DeleteInstallArtifactsReply,
    // v0.3 — DenyNotify (tag 0x12)
    DenyNotify,
    DenyNotifyAck,
    // v1.0 — DisableCuratedRule (tag 0x16)
    DisableCuratedRule,
    DisableCuratedRuleReply,
    // v0.2
    DylibLoaded,
    DylibLoadedAck,
    // v1.0 — EnableCuratedRule (tag 0x17)
    EnableCuratedRule,
    EnableCuratedRuleReply,
    EnvNotPropagatedGap,
    EnvNotPropagatedGapAck,
    ExecAck,
    // v0.4 — ExecBlocked (tag 0x13)
    ExecBlocked,
    ExecBlockedAck,
    ExecEvent,
    ForkAck,
    ForkEvent,
    GapInfo,
    // v0.3 — InsertUserRule (tag 0x0B)
    InsertUserRule,
    InsertUserRuleReply,
    InstallArtifact,
    InstallInfo,
    IntelMatch,
    // v0.7 — ListRules (tag 0x0E)
    ListRules,
    ListRulesReply,
    // v0.3 — Prompt request/response/cancel (channel-internal)
    PackageContext,
    // v0.4 — PersistenceWrite (tag 0x14)
    PersistenceWrite,
    PersistenceWriteAck,
    // v0.5 — Ping (tag 0x15; watchdog liveness)
    Ping,
    PingReply,
    PrepareSnapshot,
    ProcessCtx,
    PromptCancel,
    // v0.3 — Prompt channel (tag 0x0A)
    PromptChannelInit,
    PromptChannelInitAck,
    PromptRequest,
    PromptResponse,
    PromptVerdict,
    ProposedRule,
    PublishSignedSnapshot,
    // v0.3 — ReadInstallArtifacts (tag 0x0C)
    ReadInstallArtifacts,
    ReadInstallArtifactsReply,
    RegisterRoot,
    Reply,
    Resolve,
    ResolveReply,
    RulePattern,
    RuleRow,
    SigningInfo,
    SnapshotInputsReply,
    SnapshotReply,
    Status,
    StatusCounters,
    StatusReply,
    SuggestedRule,
    TrackedRootInfo,
    IPC_SCHEMA_V1,
    IPC_SCHEMA_V2,
    // v0.3
    IPC_SCHEMA_V3,
    // v0.4 — Threat-intel
    IPC_SCHEMA_V4,
    // v0.8 — signed persistent user rules
    IPC_SCHEMA_V5,
    SOCKADDR_WIRE_LEN,
};
