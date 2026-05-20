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
    pub schema_version: u16, // FIRST field — must equal IPC_SCHEMA_V1
    pub audit_token: AuditTokenWire,
    #[serde(default)]
    pub run_uuid: Option<String>,
    #[serde(default)]
    pub pm_env: Vec<(String, String)>,
}

impl RegisterRoot {
    pub fn new(token: sentinel_core::AuditToken) -> Self {
        Self {
            schema_version: IPC_SCHEMA_V1,
            audit_token: AuditTokenWire::from(token),
            run_uuid: None,
            pm_env: Vec::new(),
        }
    }

    pub fn new_for_run(token: sentinel_core::AuditToken, run_uuid: impl Into<String>) -> Self {
        Self {
            schema_version: IPC_SCHEMA_V1,
            audit_token: AuditTokenWire::from(token),
            run_uuid: Some(run_uuid.into()),
            pm_env: Vec::new(),
        }
    }

    pub fn new_for_run_with_pm_env(
        token: sentinel_core::AuditToken,
        run_uuid: impl Into<String>,
        pm_env: Vec<(String, String)>,
    ) -> Self {
        Self {
            schema_version: IPC_SCHEMA_V1,
            audit_token: AuditTokenWire::from(token),
            run_uuid: Some(run_uuid.into()),
            pm_env,
        }
    }
}

/// Daemon → CLI: response to RegisterRoot.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum Reply {
    Ack {
        schema_version: u16,
    },
    Err {
        schema_version: u16,
        message: String,
    },
}

impl Reply {
    pub fn ack() -> Self {
        Reply::Ack {
            schema_version: IPC_SCHEMA_V1,
        }
    }

    pub fn err(m: impl Into<String>) -> Self {
        Reply::Err {
            schema_version: IPC_SCHEMA_V1,
            message: m.into(),
        }
    }

    pub fn schema(&self) -> u16 {
        match self {
            Reply::Ack { schema_version } | Reply::Err { schema_version, .. } => *schema_version,
        }
    }
}

// ============================================================================
// v0.2 message types.
//
// Existing `RegisterRoot` + `Reply` are FROZEN at IPC_SCHEMA_V1=1 and unchanged.
// Every new message has `schema_version: u16` as its FIRST field (or first
// field of every enum variant). Recipients verify the field equals
// `IPC_SCHEMA_V2` and reject otherwise.
// ============================================================================

pub const IPC_SCHEMA_V2: u16 = 2;
pub const IPC_SCHEMA_V3: u16 = 3;
pub const IPC_SCHEMA_V4: u16 = 4;

// ============================================================
// v0.4 — Threat-intel match record + non-fatal feed warning.
// ============================================================

/// Per-feed match record attached to JSONL block-log entries via the `intel`
/// array, and to PromptRequest for pre-prompt enrichment. Multiple matches
/// preserve cross-feed cross-reference (a malicious package present in both
/// OSV and GHSA shows two rows).
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct IntelMatch {
    pub feed: String, // "OSV" | "GHSA"
    pub advisory_id: String,
    pub source: String, // "package" | "host"
    pub severity: Option<String>,
    pub tag: Option<String>,
    pub first_seen_ms: u64,
}

// --- PrepareSnapshot / SnapshotReply ----------------------------------------

/// CLI → daemon: sent BEFORE posix_spawn. Daemon merges curated YAML + SQLite
/// rules, writes per-run snapshot, returns the manifest path the CLI will set
/// as SENTINEL_SNAPSHOT_MANIFEST.
///
/// V3 additions: `is_tty` and `baseline_mode`. Both are
/// `#[serde(default)]` so V2-encoded messages decode cleanly with false.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct PrepareSnapshot {
    pub schema_version: u16, // V2 or V3 — daemon accepts both
    pub cwd: String,
    #[serde(default)]
    pub is_tty: bool, // V3 addition. Default false on V2 decode.
    #[serde(default)]
    pub baseline_mode: bool, // V3 addition. Default false on V2 decode.
}

impl PrepareSnapshot {
    /// V2-compatible constructor — emits V2 schema_version; new fields default false.
    /// Existing callers do NOT break.
    pub fn new(cwd: impl Into<String>) -> Self {
        Self {
            schema_version: IPC_SCHEMA_V2,
            cwd: cwd.into(),
            is_tty: false,
            baseline_mode: false,
        }
    }

    /// V3 constructor — opt-in to the new TTY and baseline-mode fields.
    pub fn new_v3(cwd: impl Into<String>, is_tty: bool, baseline_mode: bool) -> Self {
        Self {
            schema_version: IPC_SCHEMA_V3,
            cwd: cwd.into(),
            is_tty,
            baseline_mode,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum SnapshotReply {
    Ok {
        schema_version: u16,
        manifest_path: String,
        run_uuid: String,
    },
    Err {
        schema_version: u16,
        message: String,
    },
}

impl SnapshotReply {
    pub fn ok(manifest_path: impl Into<String>, run_uuid: impl Into<String>) -> Self {
        Self::Ok {
            schema_version: IPC_SCHEMA_V2,
            manifest_path: manifest_path.into(),
            run_uuid: run_uuid.into(),
        }
    }

    pub fn err(message: impl Into<String>) -> Self {
        Self::Err {
            schema_version: IPC_SCHEMA_V2,
            message: message.into(),
        }
    }
}

// --- ForkEvent / ForkAck ----------------------------------------------------

/// Dylib → daemon: a fork(2) / vfork(2) / posix_spawn completed in a tracked
/// process. Sent synchronously: the dylib blocks until ForkAck.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ForkEvent {
    pub schema_version: u16,
    pub parent_audit_token: AuditTokenWire,
    pub child_pid: i32,
    pub child_pidversion: u32,
}

impl ForkEvent {
    pub fn new(parent: AuditTokenWire, child_pid: i32, child_pidversion: u32) -> Self {
        Self {
            schema_version: IPC_SCHEMA_V2,
            parent_audit_token: parent,
            child_pid,
            child_pidversion,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum ForkAck {
    Ok {
        schema_version: u16,
    },
    Err {
        schema_version: u16,
        message: String,
    },
}

impl ForkAck {
    pub fn ok() -> Self {
        Self::Ok {
            schema_version: IPC_SCHEMA_V2,
        }
    }
    pub fn err(m: impl Into<String>) -> Self {
        Self::Err {
            schema_version: IPC_SCHEMA_V2,
            message: m.into(),
        }
    }
}

// --- ExecEvent / ExecAck ----------------------------------------------------

/// Dylib → daemon: an execve / posix_spawn / exec* call is being made.
/// `target_path` is the binary the calling process is about to load. The
/// daemon uses csops(CS_OPS_STATUS) on the calling process's pid to decide
/// if exec into target will strip DYLD env vars.
///
/// SECURITY: the wire allows arbitrary length but the daemon
/// handler MUST reject `target_path.len() > 1024`. The dylib MUST cap copy
/// at 1024 bytes before sending.
///
/// V3 addition: `pm_env` carries package-manager environment variables
/// captured at exec time (e.g. npm_package_name, npm_lifecycle_event).
/// `#[serde(default)]` ensures V2-encoded messages decode with empty pm_env.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ExecEvent {
    pub schema_version: u16,
    pub audit_token: AuditTokenWire,
    #[serde(with = "serde_bytes")]
    pub target_path: Vec<u8>,
    #[serde(default)]
    pub pm_env: Vec<(String, String)>, // V3 addition. Cap MAX_PM_ENV_BYTES total wire bytes.
}

impl ExecEvent {
    /// Maximum acceptable target_path length. Senders MUST cap;
    /// receivers MUST reject longer payloads.
    pub const MAX_TARGET_PATH: usize = 1024;

    /// Maximum total wire bytes for pm_env key+value pairs.
    pub const MAX_PM_ENV_BYTES: usize = 4096;

    /// V2-compatible constructor — emits V2 schema_version; pm_env defaults to empty.
    pub fn new(token: AuditTokenWire, target_path: Vec<u8>) -> Self {
        Self {
            schema_version: IPC_SCHEMA_V2,
            audit_token: token,
            target_path,
            pm_env: Vec::new(),
        }
    }

    /// V3 constructor — includes pm_env key-value pairs.
    pub fn new_v3(
        audit_token: AuditTokenWire,
        target_path: Vec<u8>,
        pm_env: Vec<(String, String)>,
    ) -> Self {
        Self {
            schema_version: IPC_SCHEMA_V3,
            audit_token,
            target_path,
            pm_env,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum ExecAck {
    Ok {
        schema_version: u16,
    },
    Err {
        schema_version: u16,
        message: String,
    },
}

impl ExecAck {
    pub fn ok() -> Self {
        Self::Ok {
            schema_version: IPC_SCHEMA_V2,
        }
    }
    pub fn err(m: impl Into<String>) -> Self {
        Self::Err {
            schema_version: IPC_SCHEMA_V2,
            message: m.into(),
        }
    }
}

// --- DylibLoaded / DylibLoadedAck -------------------------------------------

/// Dylib → daemon: dylib ctor reached the end successfully. Confirms injection
/// for two-step gap detection (closes the post-exec timeout window).
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct DylibLoaded {
    pub schema_version: u16,
    pub audit_token: AuditTokenWire,
}

impl DylibLoaded {
    pub fn new(token: AuditTokenWire) -> Self {
        Self {
            schema_version: IPC_SCHEMA_V2,
            audit_token: token,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum DylibLoadedAck {
    Ok {
        schema_version: u16,
    },
    Err {
        schema_version: u16,
        message: String,
    },
}

impl DylibLoadedAck {
    pub fn ok() -> Self {
        Self::Ok {
            schema_version: IPC_SCHEMA_V2,
        }
    }
    pub fn err(m: impl Into<String>) -> Self {
        Self::Err {
            schema_version: IPC_SCHEMA_V2,
            message: m.into(),
        }
    }
}

// --- Resolve / ResolveReply (getaddrinfo daemon-proxy) ---------------------

/// Dylib → daemon: resolve `host:port` via the daemon's un-interposed libc.
/// Replaces the dropped v0.1 getaddrinfo interpose. Result cached in
/// the dylib's per-process getaddrinfo-cache.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Resolve {
    pub schema_version: u16,
    pub host: String,
    pub port: u16,
}

impl Resolve {
    pub fn new(host: impl Into<String>, port: u16) -> Self {
        Self {
            schema_version: IPC_SCHEMA_V2,
            host: host.into(),
            port,
        }
    }
}

/// 28 bytes = sizeof(sockaddr_in6) on Darwin — fits both AF_INET and AF_INET6
/// addresses with room for the family/length prefix.
pub const SOCKADDR_WIRE_LEN: usize = 28;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum ResolveReply {
    Addresses {
        schema_version: u16,
        addrs: Vec<[u8; SOCKADDR_WIRE_LEN]>,
    },
    Deny {
        schema_version: u16,
        reason: String,
    },
    Err {
        schema_version: u16,
        message: String,
    },
}

impl ResolveReply {
    pub fn addresses(addrs: Vec<[u8; SOCKADDR_WIRE_LEN]>) -> Self {
        Self::Addresses {
            schema_version: IPC_SCHEMA_V2,
            addrs,
        }
    }
    pub fn deny(reason: impl Into<String>) -> Self {
        Self::Deny {
            schema_version: IPC_SCHEMA_V2,
            reason: reason.into(),
        }
    }
    pub fn err(message: impl Into<String>) -> Self {
        Self::Err {
            schema_version: IPC_SCHEMA_V2,
            message: message.into(),
        }
    }
}

// --- EnvNotPropagatedGap / Ack -----------------------------------------------

/// Dylib → daemon: parent process detected pre-spawn that the envp passed to
/// libc::posix_spawn is missing one or more required Sentinel env vars
/// (DYLD_INSERT_LIBRARIES, SENTINEL_DAEMON_SOCKET, or SENTINEL_SNAPSHOT_MANIFEST).
/// The about-to-be-spawned child cannot inherit the dylib injection.
///
/// This is informational (not enforcement) — the dylib emits the IPC and
/// continues; the daemon records the gap on the PARENT's ProcessNode (the child
/// does not yet exist at pre-spawn time).
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct EnvNotPropagatedGap {
    pub schema_version: u16,
    pub parent_audit_token: AuditTokenWire,
    #[serde(with = "serde_bytes")]
    pub child_binary_path: Vec<u8>, // capped at MAX_TARGET_PATH = 1024 (mirror ExecEvent contract)
    pub detected_at_ms: u64,
}

impl EnvNotPropagatedGap {
    pub const MAX_TARGET_PATH: usize = 1024;

    pub fn new(parent: AuditTokenWire, path: Vec<u8>, ts_ms: u64) -> Self {
        let mut p = path;
        if p.len() > Self::MAX_TARGET_PATH {
            p.truncate(Self::MAX_TARGET_PATH);
        }
        Self {
            schema_version: IPC_SCHEMA_V2,
            parent_audit_token: parent,
            child_binary_path: p,
            detected_at_ms: ts_ms,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum EnvNotPropagatedGapAck {
    Ok {
        schema_version: u16,
    },
    Err {
        schema_version: u16,
        message: String,
    },
}

impl EnvNotPropagatedGapAck {
    pub fn ok() -> Self {
        Self::Ok {
            schema_version: IPC_SCHEMA_V2,
        }
    }
    pub fn err(m: impl Into<String>) -> Self {
        Self::Err {
            schema_version: IPC_SCHEMA_V2,
            message: m.into(),
        }
    }
}

// ============================================================
// v0.3 — Status IPC (tag 0x09)
// ============================================================

/// CLI → daemon: request daemon state and counters.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Status {
    pub schema_version: u16, // V3
}

impl Status {
    pub fn new() -> Self {
        Self {
            schema_version: IPC_SCHEMA_V3,
        }
    }
}

impl Default for Status {
    fn default() -> Self {
        Self::new()
    }
}

/// Discriminant for daemon health state — used in StatusReply.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum DaemonStateKind {
    Degraded,
    Operational,
}

/// Summary of a tracked (wrapped) root invocation.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct TrackedRootInfo {
    pub run_uuid: String,
    pub audit_token: AuditTokenWire,
    pub argv: Vec<String>, // root argv truncated to 256B per element
    pub started_at_ms: u64,
}

/// Coverage gap event detected during a run.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct GapInfo {
    pub run_uuid: String,
    pub gap_kind: String, // "hardened-runtime" | "env-not-propagated"
    pub binary_path: Option<String>,
    pub detected_at_ms: u64,
}

/// Aggregate counters reported by daemon status.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct StatusCounters {
    pub rules_user: u64,
    pub blocks_today: u64,
    pub allows_today: u64,
    pub gaps_today: u64,
}

/// Single install artifact recorded by `sentinel install`.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct InstallArtifact {
    pub artifact_kind: String, // "launchagent"|"marker_block"|"init_script"|"state_dir"|"log_dir"|"binary"
    pub target_path: String,
    pub installed_at_ms: u64,
    pub content_hash: Option<String>,
    pub sentinel_version: String,
}

/// Aggregated install metadata returned by ReadInstallArtifacts or StatusReply.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct InstallInfo {
    pub version: String, // sentinel-cli compile-time version
    pub installed_at_ms: u64,
    pub artifacts: Vec<InstallArtifact>,
}

/// Daemon → CLI: response to Status request.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum StatusReply {
    Ok {
        schema_version: u16,
        daemon_state: DaemonStateKind,
        tracked_roots: Vec<TrackedRootInfo>,
        recent_gaps: Vec<GapInfo>,
        counters: StatusCounters,
        install_info: Option<InstallInfo>,
    },
    Err {
        schema_version: u16,
        message: String,
    },
}

impl StatusReply {
    pub fn ok(
        daemon_state: DaemonStateKind,
        tracked_roots: Vec<TrackedRootInfo>,
        recent_gaps: Vec<GapInfo>,
        counters: StatusCounters,
        install_info: Option<InstallInfo>,
    ) -> Self {
        Self::Ok {
            schema_version: IPC_SCHEMA_V3,
            daemon_state,
            tracked_roots,
            recent_gaps,
            counters,
            install_info,
        }
    }
    pub fn err(message: impl Into<String>) -> Self {
        Self::Err {
            schema_version: IPC_SCHEMA_V3,
            message: message.into(),
        }
    }
}

// ============================================================
// v0.3 — Prompt channel init (tag 0x0A; LONG-LIVED)
// After init+ack, channel-internal frames are un-tagged length-prefixed CBOR.
// ============================================================

/// CLI → daemon: open a long-lived prompt channel tied to a run.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct PromptChannelInit {
    pub schema_version: u16, // V3
    pub run_uuid: String,    // ties channel to RunRecord
}

/// Daemon → CLI: response to PromptChannelInit.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum PromptChannelInitAck {
    Ok {
        schema_version: u16,
    },
    Err {
        schema_version: u16,
        message: String,
    },
}

impl PromptChannelInitAck {
    pub fn ok() -> Self {
        Self::Ok {
            schema_version: IPC_SCHEMA_V3,
        }
    }
    pub fn err(message: impl Into<String>) -> Self {
        Self::Err {
            schema_version: IPC_SCHEMA_V3,
            message: message.into(),
        }
    }
}

// ============================================================
// v0.3 — Prompt request/response/cancel (channel-internal; no tag byte)
// ============================================================

/// Package-manager context for a prompt — identifies which package triggered the connection.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct PackageContext {
    pub ecosystem: String, // "npm"|"pip"|"cargo"|"bundle"|"gem"|"go"|"mix"|"hex"|"composer"
    pub package: String,
    pub version: String,
    pub lifecycle: Option<String>, // "postinstall"|"install"|"build"|null
    pub root_command: String,      // argv.join(' ') truncated to 256
}

/// Process context snapshot at the time of a connection attempt.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProcessCtx {
    pub pid: u32,
    pub pidversion: u32,
    pub argv0: String,
    pub cwd: String,
}

/// Suggested rule for the user to consider when approving/denying.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct SuggestedRule {
    pub match_type: String, // "exact"|"suffix"
    pub pattern: String,
}

/// Daemon → CLI (prompt channel): request user decision on an outbound connection.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct PromptRequest {
    pub schema_version: u16, // V3
    pub prompt_id: String,   // UUID v4
    pub dest_host: String,
    pub dest_port: u16,
    pub dest_ip: Option<String>,
    pub source_kind: String, // v0.2 enum string repr
    pub source_locator: Option<String>,
    pub package_context: Option<PackageContext>,
    pub process: ProcessCtx,
    /// v0.4 type unification: changed from `Option<()>` placeholder
    /// to `Option<Vec<IntelMatch>>`. Populating prompt-time enrichment is
    /// deferred to v2. Existing `intel: None` callers remain valid since
    /// `None` is still a valid value for the new type.
    pub intel: Option<Vec<IntelMatch>>,
    pub suggested_rules: Vec<SuggestedRule>,
}

/// User's verdict on a prompt request.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum PromptVerdict {
    AllowOnce,
    AllowAlwaysMachine,
    Deny,
}

/// Rule pattern for a user-approved or -denied connection pattern.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct RulePattern {
    pub match_type: String, // "exact"|"suffix"
    pub pattern: String,
}

/// CLI → daemon (prompt channel): user's decision on a PromptRequest.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct PromptResponse {
    pub schema_version: u16, // V3
    pub prompt_id: String,
    pub verdict: PromptVerdict,
    pub rule_pattern: Option<RulePattern>,
}

/// CLI → daemon (prompt channel): cancel an outstanding prompt (e.g. timeout or Ctrl-C).
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct PromptCancel {
    pub schema_version: u16, // V3
    pub prompt_id: String,
}

// ============================================================
// v0.3 — InsertUserRule (tag 0x0B; sentinel approve)
// ============================================================

/// CLI → daemon: insert a user-authored rule into the SQLite rule store.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct InsertUserRule {
    pub schema_version: u16, // V3
    pub kind: String,        // "allow"|"deny"
    pub match_type: String,  // "exact"|"suffix"|"ip"
    pub pattern: String,
    pub reason: String, // non-empty
}

/// Daemon → CLI: response to InsertUserRule.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum InsertUserRuleReply {
    Ok {
        schema_version: u16,
        rule_id: i64,
    },
    Err {
        schema_version: u16,
        message: String,
    },
}

impl InsertUserRuleReply {
    pub fn ok(rule_id: i64) -> Self {
        Self::Ok {
            schema_version: IPC_SCHEMA_V3,
            rule_id,
        }
    }
    pub fn err(message: impl Into<String>) -> Self {
        Self::Err {
            schema_version: IPC_SCHEMA_V3,
            message: message.into(),
        }
    }
}

// ============================================================
// v0.3 — ReadInstallArtifacts (tag 0x0C; sentinel uninstall)
// ============================================================

/// CLI → daemon: read the install artifacts manifest (for uninstall).
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReadInstallArtifacts {
    pub schema_version: u16, // V3
}

impl ReadInstallArtifacts {
    pub fn new() -> Self {
        Self {
            schema_version: IPC_SCHEMA_V3,
        }
    }
}

impl Default for ReadInstallArtifacts {
    fn default() -> Self {
        Self::new()
    }
}

/// Daemon → CLI: response to ReadInstallArtifacts.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum ReadInstallArtifactsReply {
    Ok {
        schema_version: u16,
        artifacts: Vec<InstallArtifact>,
    },
    Err {
        schema_version: u16,
        message: String,
    },
}

impl ReadInstallArtifactsReply {
    pub fn ok(artifacts: Vec<InstallArtifact>) -> Self {
        Self::Ok {
            schema_version: IPC_SCHEMA_V3,
            artifacts,
        }
    }
    pub fn err(message: impl Into<String>) -> Self {
        Self::Err {
            schema_version: IPC_SCHEMA_V3,
            message: message.into(),
        }
    }
}

// ============================================================
// v0.3 — BaselineCommit (tag 0x0D; sentinel wrap --baseline exit)
// ============================================================

/// CLI → daemon: commit an accumulated baseline run into proposed rules.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct BaselineCommit {
    pub schema_version: u16, // V3
    pub run_uuid: String,
}

/// A single rule proposed by the baseline commit process.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProposedRule {
    pub match_type: String, // "exact"|"suffix"
    pub pattern: String,
    pub reason: String, // "baseline: recorded YYYY-MM-DD by sentinel wrap --baseline"
}

/// Daemon → CLI: response to BaselineCommit.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum BaselineCommitReply {
    Ok {
        schema_version: u16,
        proposed_rules: Vec<ProposedRule>,
    },
    Err {
        schema_version: u16,
        message: String,
    },
}

impl BaselineCommitReply {
    pub fn ok(proposed_rules: Vec<ProposedRule>) -> Self {
        Self::Ok {
            schema_version: IPC_SCHEMA_V3,
            proposed_rules,
        }
    }
    pub fn err(message: impl Into<String>) -> Self {
        Self::Err {
            schema_version: IPC_SCHEMA_V3,
            message: message.into(),
        }
    }
}

// ============================================================
// v0.7 — ListRules (tag 0x0E; sentinel status rules)
// ============================================================

/// CLI → daemon: enumerate rules visible to the daemon.
///
/// Additive at IPC_SCHEMA_V3. The management-IPC family lives at the V3
/// schema level — new tag, new wire shape, no schema bump because this
/// neither modifies an existing message body nor breaks an existing
/// discriminator.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ListRules {
    pub schema_version: u16, // V3
    /// Include built-in registry-allowlist rules in the response (CLI: --all).
    pub include_builtins: bool,
}

impl ListRules {
    pub fn new(include_builtins: bool) -> Self {
        Self {
            schema_version: IPC_SCHEMA_V3,
            include_builtins,
        }
    }
}

impl Default for ListRules {
    fn default() -> Self {
        Self::new(false)
    }
}

/// Wire-friendly rule row. String discriminators match the InsertUserRule
/// convention; downstream tooling can pattern-match on `source` / `kind` /
/// `match_type` strings without importing core enum types.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct RuleRow {
    pub source: String,     // "user" | "builtin"
    pub kind: String,       // "allow" | "deny"
    pub match_type: String, // "exact" | "suffix" | "ip"
    pub pattern: String,
    pub reason: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum ListRulesReply {
    Ok {
        schema_version: u16,
        rules: Vec<RuleRow>,
    },
    Err {
        schema_version: u16,
        message: String,
    },
}

impl ListRulesReply {
    pub fn ok(rules: Vec<RuleRow>) -> Self {
        Self::Ok {
            schema_version: IPC_SCHEMA_V3,
            rules,
        }
    }
    pub fn err(message: impl Into<String>) -> Self {
        Self::Err {
            schema_version: IPC_SCHEMA_V3,
            message: message.into(),
        }
    }
}

// ============================================================
// v0.7 — DeleteInstallArtifacts (tag 0x11; per-target
// remove of install_artifacts rows). Symmetric of the existing
// ReadInstallArtifacts handler. Used by `setup [target] --remove`
// so the install_artifacts table reflects on-disk reality after
// a per-target wipe.
// ============================================================

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct DeleteInstallArtifacts {
    pub schema_version: u16, // V3
    /// artifact_kind values to remove. The daemon iterates each value
    /// and calls InstallArtifactStore::delete_by_kind for it.
    /// Caller-controlled vocabulary: "launchagent" | "binary" |
    /// "marker_block" | "init_script" | "state_dir" | "log_dir".
    /// Unknown kinds are accepted (delete is a no-op for unmatched rows).
    pub kinds: Vec<String>,
}

impl DeleteInstallArtifacts {
    pub fn new(kinds: Vec<String>) -> Self {
        Self {
            schema_version: IPC_SCHEMA_V3,
            kinds,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum DeleteInstallArtifactsReply {
    Ok {
        schema_version: u16,
        removed: u64,
    },
    Err {
        schema_version: u16,
        message: String,
    },
}

impl DeleteInstallArtifactsReply {
    pub fn ok(removed: u64) -> Self {
        Self::Ok {
            schema_version: IPC_SCHEMA_V3,
            removed,
        }
    }
    pub fn err(message: impl Into<String>) -> Self {
        Self::Err {
            schema_version: IPC_SCHEMA_V3,
            message: message.into(),
        }
    }
}

// ============================================================
// v0.3 — DenyNotify (tag 0x12; deny-notify IPC)
// ============================================================

/// Dylib → daemon: a libc-level denial just happened. Fire-and-forget with
/// short timeouts — the denial has already been enforced; this message only
/// provides forensic logging.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct DenyNotify {
    pub schema_version: u16, // IPC_SCHEMA_V4
    pub audit_token: AuditTokenWire,
    pub dest_host: Option<String>,
    pub dest_port: u16,
    pub dest_ip: Option<String>,
    /// Which libc surface triggered the denial.
    pub source_surface: String, // "connect"|"connectx"|"sendto"|"sendmsg"
    pub denied_at_ms: u64,
    /// Policy tier that caused the denial (e.g. "feed-deny", "default-deny").
    #[serde(default)]
    pub source_kind: String,
}

impl DenyNotify {
    pub fn new(
        audit_token: AuditTokenWire,
        dest_host: Option<String>,
        dest_port: u16,
        dest_ip: Option<String>,
        source_surface: impl Into<String>,
        denied_at_ms: u64,
        source_kind: impl Into<String>,
    ) -> Self {
        Self {
            schema_version: IPC_SCHEMA_V4,
            audit_token,
            dest_host,
            dest_port,
            dest_ip,
            source_surface: source_surface.into(),
            denied_at_ms,
            source_kind: source_kind.into(),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum DenyNotifyAck {
    Ok {
        schema_version: u16,
    },
    Err {
        schema_version: u16,
        message: String,
    },
}

impl DenyNotifyAck {
    pub fn ok() -> Self {
        Self::Ok {
            schema_version: IPC_SCHEMA_V4,
        }
    }
    pub fn err(m: impl Into<String>) -> Self {
        Self::Err {
            schema_version: IPC_SCHEMA_V4,
            message: m.into(),
        }
    }
}

// ============================================================
// v0.4 — ExecBlocked (tag 0x13; hardened-runtime exec blocking)
// ============================================================

/// Dylib → daemon: a hardened-runtime exec was blocked. Fire-and-forget.
/// The exec has already been denied (errno = EACCES); this message provides
/// forensic logging so the denial appears in the JSONL log and status output.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ExecBlocked {
    pub schema_version: u16,
    pub audit_token: AuditTokenWire,
    #[serde(with = "serde_bytes")]
    pub target_path: Vec<u8>,
    pub reason: String,
    pub blocked_at_ms: u64,
}

impl ExecBlocked {
    pub const MAX_TARGET_PATH: usize = 1024;

    pub fn new(
        audit_token: AuditTokenWire,
        target_path: &[u8],
        reason: impl Into<String>,
        blocked_at_ms: u64,
    ) -> Self {
        let len = target_path.len().min(Self::MAX_TARGET_PATH);
        Self {
            schema_version: IPC_SCHEMA_V4,
            audit_token,
            target_path: target_path[..len].to_vec(),
            reason: reason.into(),
            blocked_at_ms,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum ExecBlockedAck {
    Ok {
        schema_version: u16,
    },
    Err {
        schema_version: u16,
        message: String,
    },
}

impl ExecBlockedAck {
    pub fn ok() -> Self {
        Self::Ok {
            schema_version: IPC_SCHEMA_V4,
        }
    }
    pub fn err(m: impl Into<String>) -> Self {
        Self::Err {
            schema_version: IPC_SCHEMA_V4,
            message: m.into(),
        }
    }
}

// ============================================================================
// v0.4 — PersistenceWrite (tag 0x14)
// ============================================================================

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct PersistenceWrite {
    pub schema_version: u16,
    pub audit_token: AuditTokenWire,
    #[serde(with = "serde_bytes")]
    pub target_path: Vec<u8>,
    pub category: String,
    pub detected_at_ms: u64,
}

impl PersistenceWrite {
    pub const MAX_TARGET_PATH: usize = 1024;

    pub fn new(
        audit_token: AuditTokenWire,
        target_path: &[u8],
        category: impl Into<String>,
        detected_at_ms: u64,
    ) -> Self {
        let len = target_path.len().min(Self::MAX_TARGET_PATH);
        Self {
            schema_version: IPC_SCHEMA_V4,
            audit_token,
            target_path: target_path[..len].to_vec(),
            category: category.into(),
            detected_at_ms,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum PersistenceWriteAck {
    Ok {
        schema_version: u16,
    },
    Err {
        schema_version: u16,
        message: String,
    },
}

impl PersistenceWriteAck {
    pub fn ok() -> Self {
        Self::Ok {
            schema_version: IPC_SCHEMA_V4,
        }
    }
    pub fn err(m: impl Into<String>) -> Self {
        Self::Err {
            schema_version: IPC_SCHEMA_V4,
            message: m.into(),
        }
    }
}

// ============================================================
// v1.0 — DisableCuratedRule (tag 0x16; sentinel rules disable)
// ============================================================

/// CLI → daemon: disable a curated (built-in) rule by pattern.
/// Used when a trusted source is compromised and the user wants to
/// immediately revoke the curated allowlist entry.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct DisableCuratedRule {
    pub schema_version: u16, // V3
    pub pattern: String,
    pub reason: String, // non-empty
}

impl DisableCuratedRule {
    pub fn new(pattern: impl Into<String>, reason: impl Into<String>) -> Self {
        Self {
            schema_version: IPC_SCHEMA_V3,
            pattern: pattern.into(),
            reason: reason.into(),
        }
    }
}

/// Daemon → CLI: response to DisableCuratedRule.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum DisableCuratedRuleReply {
    Ok {
        schema_version: u16,
    },
    Err {
        schema_version: u16,
        message: String,
    },
}

impl DisableCuratedRuleReply {
    pub fn ok() -> Self {
        Self::Ok {
            schema_version: IPC_SCHEMA_V3,
        }
    }
    pub fn err(message: impl Into<String>) -> Self {
        Self::Err {
            schema_version: IPC_SCHEMA_V3,
            message: message.into(),
        }
    }
}

// ============================================================
// v1.0 — EnableCuratedRule (tag 0x17; sentinel rules enable)
// ============================================================

/// CLI → daemon: re-enable a previously disabled curated rule.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct EnableCuratedRule {
    pub schema_version: u16, // V3
    pub pattern: String,
}

impl EnableCuratedRule {
    pub fn new(pattern: impl Into<String>) -> Self {
        Self {
            schema_version: IPC_SCHEMA_V3,
            pattern: pattern.into(),
        }
    }
}

/// Daemon → CLI: response to EnableCuratedRule.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum EnableCuratedRuleReply {
    Ok {
        schema_version: u16,
        /// Whether a row was actually removed (false = pattern was not disabled).
        was_disabled: bool,
    },
    Err {
        schema_version: u16,
        message: String,
    },
}

impl EnableCuratedRuleReply {
    pub fn ok(was_disabled: bool) -> Self {
        Self::Ok {
            schema_version: IPC_SCHEMA_V3,
            was_disabled,
        }
    }
    pub fn err(message: impl Into<String>) -> Self {
        Self::Err {
            schema_version: IPC_SCHEMA_V3,
            message: message.into(),
        }
    }
}

// ============================================================================
// v0.5 — Ping (tag 0x15; watchdog liveness check)
// ============================================================================

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Ping {
    pub schema_version: u16,
}

impl Ping {
    pub fn new() -> Self {
        Self {
            schema_version: IPC_SCHEMA_V4,
        }
    }
}

impl Default for Ping {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum PingReply {
    Pong {
        schema_version: u16,
        pid: u32,
        uptime_secs: u64,
    },
    Err {
        schema_version: u16,
        message: String,
    },
}

impl PingReply {
    pub fn pong(pid: u32, uptime_secs: u64) -> Self {
        Self::Pong {
            schema_version: IPC_SCHEMA_V4,
            pid,
            uptime_secs,
        }
    }
    pub fn err(m: impl Into<String>) -> Self {
        Self::Err {
            schema_version: IPC_SCHEMA_V4,
            message: m.into(),
        }
    }
}
