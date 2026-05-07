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
    TrustPolicy,
    TrustPolicyReply,
    // Phase 3
    IPC_SCHEMA_V3,
    // Phase 3 — Status (tag 0x09)
    DaemonStateKind,
    FeedInfo,
    GapInfo,
    InstallArtifact,
    InstallInfo,
    Status,
    StatusCounters,
    StatusReply,
    TrackedRootInfo,
    // Phase 3 — Prompt channel (tag 0x0A)
    PromptChannelInit,
    PromptChannelInitAck,
    // Phase 3 — Prompt request/response/cancel (channel-internal)
    PackageContext,
    ProcessCtx,
    PromptCancel,
    PromptRequest,
    PromptResponse,
    PromptVerdict,
    RulePattern,
    SuggestedRule,
    // Phase 3 — InsertUserRule (tag 0x0B)
    InsertUserRule,
    InsertUserRuleReply,
    // Phase 3 — ReadInstallArtifacts (tag 0x0C)
    ReadInstallArtifacts,
    ReadInstallArtifactsReply,
    // Phase 3 — BaselineCommit (tag 0x0D)
    BaselineCommit,
    BaselineCommitReply,
    ProposedRule,
    // Phase 4 — Threat-intel (D-93) and SnapshotReply::Ok V4 schema bump
    IPC_SCHEMA_V4,
    IntelMatch,
    FeedWarning,
};
