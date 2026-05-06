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
// Phase 2 message types (D-30 / D-35 / D-38 / D-42).
//
// Existing `RegisterRoot` + `Reply` are FROZEN at IPC_SCHEMA_V1=1 and unchanged.
// Every new message has `schema_version: u16` as its FIRST field (or first
// field of every enum variant). Recipients verify the field equals
// `IPC_SCHEMA_V2` and reject otherwise.
// ============================================================================

pub const IPC_SCHEMA_V2: u16 = 2;
pub const IPC_SCHEMA_V3: u16 = 3;

// --- PrepareSnapshot / SnapshotReply (D-29, D-30) --------------------------

/// CLI → daemon: sent BEFORE posix_spawn. Daemon walks up cwd to .sentinel.toml,
/// merges curated YAML + SQLite + project rules, writes per-run snapshot,
/// returns the manifest path the CLI will set as SENTINEL_SNAPSHOT_MANIFEST.
///
/// V3 additions: `is_tty` (D-73) and `baseline_mode` (D-58). Both are
/// `#[serde(default)]` so V2-encoded messages decode cleanly with false.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct PrepareSnapshot {
    pub schema_version: u16,  // V2 or V3 — daemon accepts both (D-73, D-58)
    pub cwd: String,
    #[serde(default)]
    pub is_tty: bool,         // NEW V3 (D-73). Default false on V2 decode.
    #[serde(default)]
    pub baseline_mode: bool,  // NEW V3 (D-58). Default false on V2 decode.
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

// --- ForkEvent / ForkAck (D-31, D-32) --------------------------------------

/// Dylib → daemon: a fork(2) / vfork(2) / posix_spawn completed in a tracked
/// process. Sent SYNCHRONOUSLY (D-31): the dylib blocks until ForkAck.
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
    Ok { schema_version: u16 },
    Err { schema_version: u16, message: String },
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

// --- ExecEvent / ExecAck (D-31, D-32) --------------------------------------

/// Dylib → daemon: an execve / posix_spawn / exec* call is being made.
/// `target_path` is the binary the calling process is about to load. The
/// daemon uses this in D-34 Phase A: csops(CS_OPS_STATUS) on the calling
/// process's pid to decide if exec into target will strip DYLD env vars.
///
/// SECURITY (T-02-01-06): the wire allows arbitrary length but the daemon
/// handler MUST reject `target_path.len() > 1024`. The dylib MUST cap copy
/// at 1024 bytes before sending.
///
/// V3 addition: `pm_env` (D-55) carries package-manager environment variables
/// captured at exec time (e.g. npm_package_name, npm_lifecycle_event).
/// `#[serde(default)]` ensures V2-encoded messages decode with empty pm_env.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ExecEvent {
    pub schema_version: u16,
    pub audit_token: AuditTokenWire,
    #[serde(with = "serde_bytes")]
    pub target_path: Vec<u8>,
    #[serde(default)]
    pub pm_env: Vec<(String, String)>, // NEW V3 (D-55). Cap MAX_PM_ENV_BYTES total wire bytes.
}

impl ExecEvent {
    /// Maximum acceptable target_path length (T-02-01-06). Senders MUST cap;
    /// receivers MUST reject longer payloads.
    pub const MAX_TARGET_PATH: usize = 1024;

    /// Maximum total wire bytes for pm_env key+value pairs (T-03-02-04).
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
    Ok { schema_version: u16 },
    Err { schema_version: u16, message: String },
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

// --- DylibLoaded / DylibLoadedAck (D-35) -----------------------------------

/// Dylib → daemon: dylib ctor reached the end successfully. Confirms injection
/// for D-34's two-phase gap detection (closes the post-exec timeout window).
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
    Ok { schema_version: u16 },
    Err { schema_version: u16, message: String },
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

// --- Resolve / ResolveReply (D-42 — getaddrinfo daemon-proxy) --------------

/// Dylib → daemon: resolve `host:port` via the daemon's un-interposed libc.
/// D-42: replaces the dropped Phase 1 getaddrinfo interpose. Result cached in
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

// --- TrustPolicy / TrustPolicyReply (D-38) ---------------------------------

/// CLI → daemon: trust the (path, sha256) tuple — inserts into
/// `trusted_policy_files` SQLite table. Subsequent `sentinel run` invocations
/// from working directories below `path` will honor that .sentinel.toml.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct TrustPolicy {
    pub schema_version: u16,
    pub path: String,   // canonicalized absolute path
    pub sha256: String, // 64-char lowercase hex
}

impl TrustPolicy {
    pub fn new(path: impl Into<String>, sha256: impl Into<String>) -> Self {
        Self {
            schema_version: IPC_SCHEMA_V2,
            path: path.into(),
            sha256: sha256.into(),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum TrustPolicyReply {
    Ok { schema_version: u16 },
    Err { schema_version: u16, message: String },
}

impl TrustPolicyReply {
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

// --- EnvNotPropagatedGap / Ack (TREE-06 — gap-closure 02-09) -----------------

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
    Ok { schema_version: u16 },
    Err { schema_version: u16, message: String },
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
