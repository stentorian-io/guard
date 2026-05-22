//! Dylib-side blocking IPC client for ForkEvent / ExecEvent / DylibLoaded.
//!
//! D-31: synchronous — the calling hook blocks until the daemon Acks.
//! D-33: fail-closed-on-timeout for fork events (caller kills child + EAGAIN).
//!
//! Socket path: derived from well_known_state_dir() at ctor time — the socket
//! is always at `{state_dir}/stt-guard-daemon.sock`.
//!
//! Wire shape: each message is a `tag byte (0x03..=0x05) + length-prefixed CBOR
//! body`. The daemon's first-byte-peek dispatcher routes the tag
//! to the matching handler. The handler responds with the same tag echoed
//! followed by a length-prefixed CBOR ack body.

use core::ffi::c_char;
use guard_ipc::frame::{read_frame, write_frame};
use guard_ipc::{
    AuditTokenWire, DenyNotify, DenyNotifyAck, DylibLoaded, DylibLoadedAck, ExecAck, ExecBlocked,
    ExecBlockedAck, ExecEvent, ForkAck, ForkEvent, IPC_SCHEMA_V2, IPC_SCHEMA_V3, IPC_SCHEMA_V4,
    PersistenceWrite, PersistenceWriteAck, Resolve, ResolveReply, SOCKADDR_WIRE_LEN,
};
use socket2::{Domain, SockAddr, Socket, Type};
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use std::time::Duration;

// Tag bytes — must match the daemon's MessageTag values exactly.
pub(crate) const TAG_FORK_EVENT: u8 = 0x03;
pub(crate) const TAG_EXEC_EVENT: u8 = 0x04;
pub(crate) const TAG_DYLIB_LOADED: u8 = 0x05;
pub(crate) const TAG_RESOLVE: u8 = 0x06;
pub(crate) const TAG_ENV_NOT_PROPAGATED: u8 = 0x08;
pub(crate) const TAG_DENY_NOTIFY: u8 = 0x12;
pub(crate) const TAG_EXEC_BLOCKED: u8 = 0x13;
pub(crate) const TAG_PERSISTENCE_WRITE: u8 = 0x14;

static DAEMON_SOCKET_PATH: OnceLock<Option<PathBuf>> = OnceLock::new();
static IPC_HMAC_KEY: OnceLock<Option<[u8; 32]>> = OnceLock::new();

/// Per-test override for the daemon socket path.
///
/// OnceLock is correct for production (set once at ctor time from state dir,
/// never changes). Integration tests need a per-test override so each test can
/// point at its own stub Unix socket without racing on the OnceLock.
///
/// Tri-state: `None` = no override (fall through to OnceLock),
/// `Some(None)` = explicitly no socket (NotConfigured),
/// `Some(Some(path))` = use this path.
static TEST_SOCKET_OVERRIDE: std::sync::Mutex<Option<Option<PathBuf>>> =
    std::sync::Mutex::new(None);

/// Override the daemon socket path for the current test. Test-only by convention.
pub fn _set_daemon_socket_for_test(path: PathBuf) {
    let mut g = TEST_SOCKET_OVERRIDE
        .lock()
        .expect("test socket override mutex");
    *g = Some(Some(path));
}

/// Clear the test socket override so daemon_socket_path() returns None
/// (NotConfigured). Call this to simulate "no daemon" in tests.
pub fn _clear_daemon_socket_for_test() {
    let mut g = TEST_SOCKET_OVERRIDE
        .lock()
        .expect("test socket override mutex");
    *g = Some(None);
}

/// Remove the test override entirely, falling through to the OnceLock.
pub fn _reset_daemon_socket_for_test() {
    let mut g = TEST_SOCKET_OVERRIDE
        .lock()
        .expect("test socket override mutex");
    *g = None;
}

#[derive(Debug)]
pub enum IpcClientError {
    /// Daemon socket path not configured (e.g. unit tests, or dylib loaded
    /// outside `stt-guard wrap`). Caller treats this as "no IPC available".
    NotConfigured,
    /// Connect / read / write timed out within the budget.
    Timeout,
    /// Underlying I/O error from the socket layer.
    Io(std::io::Error),
    /// Daemon returned an `Err` ack with a message.
    DaemonRejected(String),
    /// CBOR codec error (frame too large, malformed body, tag mismatch).
    Codec(String),
}

impl From<std::io::Error> for IpcClientError {
    fn from(e: std::io::Error) -> Self {
        IpcClientError::Io(e)
    }
}

impl std::fmt::Display for IpcClientError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            IpcClientError::NotConfigured => {
                write!(f, "ipc-client: daemon socket path not configured")
            }
            IpcClientError::Timeout => write!(f, "ipc-client: timeout"),
            IpcClientError::Io(e) => write!(f, "ipc-client: io: {e}"),
            IpcClientError::DaemonRejected(m) => write!(f, "ipc-client: daemon-rejected: {m}"),
            IpcClientError::Codec(m) => write!(f, "ipc-client: codec: {m}"),
        }
    }
}

/// Derive the daemon socket path from well_known_state_dir().
/// Idempotent — subsequent calls are no-ops. Called once from the dylib ctor.
pub fn cache_daemon_socket_path() {
    DAEMON_SOCKET_PATH.get_or_init(|| {
        let state_dir = crate::snapshot::well_known_state_dir();
        Some(guard_core::paths::socket_path(&state_dir))
    });
}

/// Cache the HMAC key from the well-known state directory. Called once from the
/// dylib ctor after snapshot load. The key is reused for per-message IPC signing.
pub fn cache_ipc_hmac_key() {
    use std::os::unix::fs::OpenOptionsExt;
    IPC_HMAC_KEY.get_or_init(|| {
        let state_dir = crate::snapshot::well_known_state_dir();
        let path = guard_core::paths::hmac_key_path(&state_dir);
        let mut f = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&path)
            .ok()?;
        let mut buf = [0u8; 32];
        let n = std::io::Read::read(&mut f, &mut buf).ok()?;
        if n != 32 {
            return None;
        }
        let mut extra = [0u8; 1];
        if std::io::Read::read(&mut f, &mut extra).ok() != Some(0) {
            return None;
        }
        Some(buf)
    });
}

fn ipc_hmac_key() -> Option<[u8; 32]> {
    IPC_HMAC_KEY.get().and_then(|o| *o)
}

/// Returns the daemon socket path. The test override (set via `_set_daemon_socket_for_test`)
/// is consulted first; in production, the OnceLock value (derived from state dir at ctor
/// time) is used.
pub fn daemon_socket_path() -> Option<PathBuf> {
    let g = TEST_SOCKET_OVERRIDE
        .lock()
        .expect("test socket override mutex");
    match &*g {
        Some(override_val) => {
            let result = override_val.clone();
            drop(g);
            return result;
        }
        None => {}
    }
    drop(g);
    DAEMON_SOCKET_PATH.get().and_then(|o| o.clone())
}

pub(crate) fn connect_with_timeout(
    sock: &Path,
    total_ms: u64,
) -> Result<UnixStream, IpcClientError> {
    let addr = SockAddr::unix(sock).map_err(IpcClientError::Io)?;
    let socket = Socket::new(Domain::UNIX, Type::STREAM, None).map_err(IpcClientError::Io)?;
    // 1/5 of total budget for connect, 2/5 each for read/write.
    let total_ms = total_ms.max(5);
    let connect_dur = Duration::from_millis(total_ms / 5);
    socket
        .connect_timeout(&addr, connect_dur)
        .map_err(IpcClientError::Io)?;
    let rw_dur = Duration::from_millis((total_ms * 2) / 5);
    socket.set_read_timeout(Some(rw_dur)).ok();
    socket.set_write_timeout(Some(rw_dur)).ok();
    // WR-02: use the safe From<Socket> for UnixStream conversion (socket2 0.5+
    // on Unix). Eliminates the unsafe raw-fd dance and its future-edit
    // hazard.
    Ok(socket.into())
}

fn map_io_to_timeout(e: std::io::Error) -> IpcClientError {
    if e.kind() == std::io::ErrorKind::TimedOut || e.kind() == std::io::ErrorKind::WouldBlock {
        IpcClientError::Timeout
    } else {
        IpcClientError::Io(e)
    }
}

pub(crate) fn send_tagged_and_recv_ack<Req, Ack>(
    tag: u8,
    msg: &Req,
    timeout_ms: u64,
) -> Result<Ack, IpcClientError>
where
    Req: serde::Serialize,
    Ack: serde::de::DeserializeOwned,
{
    let sock = daemon_socket_path().ok_or(IpcClientError::NotConfigured)?;
    let mut stream = connect_with_timeout(&sock, timeout_ms)?;
    // Tag byte first.
    stream.write_all(&[tag]).map_err(map_io_to_timeout)?;

    if let Some(key) = ipc_hmac_key() {
        let mut signer = guard_ipc::signed_frame::FrameSigner::new(key);
        signer
            .write_signed(&mut stream, tag, msg)
            .map_err(|e| IpcClientError::Codec(e.to_string()))?;
        // Read the response: tag byte (echoed by daemon) + signed body.
        let mut tag_back = [0u8; 1];
        stream
            .read_exact(&mut tag_back)
            .map_err(map_io_to_timeout)?;
        if tag_back[0] != tag {
            return Err(IpcClientError::Codec(format!(
                "tag mismatch: sent 0x{tag:02x}, got 0x{:02x}",
                tag_back[0]
            )));
        }
        let ack: Ack = signer
            .read_signed(&mut stream, tag)
            .map_err(|e| IpcClientError::Codec(e.to_string()))?;
        Ok(ack)
    } else {
        // Unsigned fallback (no HMAC key available).
        write_frame(&mut stream, msg).map_err(|e| IpcClientError::Codec(e.to_string()))?;
        let mut tag_back = [0u8; 1];
        stream
            .read_exact(&mut tag_back)
            .map_err(map_io_to_timeout)?;
        if tag_back[0] != tag {
            return Err(IpcClientError::Codec(format!(
                "tag mismatch: sent 0x{tag:02x}, got 0x{:02x}",
                tag_back[0]
            )));
        }
        let ack: Ack = read_frame(&mut stream).map_err(|e| IpcClientError::Codec(e.to_string()))?;
        Ok(ack)
    }
}

/// Synchronous round trip: sends a tagged ForkEvent frame, waits for ForkAck.
/// Returns Ok(()) on `ForkAck::Ok`, `IpcClientError::DaemonRejected(msg)` on
/// `ForkAck::Err`, `IpcClientError::Timeout` on read/write timeout.
///
/// On error the caller MUST fail-closed (D-33): kill the child, set EAGAIN.
pub fn send_fork_event_sync(
    parent_token: AuditTokenWire,
    child_pid: i32,
    child_pidversion: u32,
    timeout_ms: u64,
) -> Result<(), IpcClientError> {
    let ev = ForkEvent {
        schema_version: IPC_SCHEMA_V2,
        parent_audit_token: parent_token,
        child_pid,
        child_pidversion,
    };
    let ack: ForkAck = send_tagged_and_recv_ack(TAG_FORK_EVENT, &ev, timeout_ms)?;
    match ack {
        ForkAck::Ok { .. } => Ok(()),
        ForkAck::Err { message, .. } => Err(IpcClientError::DaemonRejected(message)),
    }
}

/// Synchronous round trip for ExecEvent. The dylib supplies `target_path` as
/// bytes already copied from the user's `path` argument; this function caps
/// the slice at `ExecEvent::MAX_TARGET_PATH (1024)` before serializing
/// (T-02-01-06 closure carry-forward).
///
/// `pm_env` is the filtered package-manager environment captured at exec
/// time (closes v0.1 milestone audit BLOCKER #1 — LOG-02 + VAL-01). Pass
/// `Vec::new()` for callers that have no envp to walk (e.g. fork-without-
/// exec); pass the result of
/// `pm_env_filter::extract_pm_env_from_envp{_mut}` for exec/posix_spawn
/// shadows.
///
/// When `pm_env` is non-empty the wire frame is upgraded to
/// `IPC_SCHEMA_V3` so the daemon's V3 handler picks up the new field;
/// when empty, the frame stays at `IPC_SCHEMA_V2` and serializes
/// identically to the previous shape (forward-compatible — daemon
/// `handle_exec_event_frame` accepts both V2 and V3).
pub fn send_exec_event_sync(
    audit_token: AuditTokenWire,
    target_path: &[u8],
    target_path_len: usize,
    pm_env: Vec<(String, String)>,
    timeout_ms: u64,
) -> Result<(), IpcClientError> {
    let len = target_path_len
        .min(target_path.len())
        .min(ExecEvent::MAX_TARGET_PATH);
    let schema_version = if pm_env.is_empty() {
        IPC_SCHEMA_V2
    } else {
        IPC_SCHEMA_V3
    };
    let ev = ExecEvent {
        schema_version,
        audit_token,
        target_path: target_path[..len].to_vec(),
        pm_env,
    };
    let ack: ExecAck = send_tagged_and_recv_ack(TAG_EXEC_EVENT, &ev, timeout_ms)?;
    match ack {
        ExecAck::Ok { .. } => Ok(()),
        ExecAck::Err { message, .. } => Err(IpcClientError::DaemonRejected(message)),
    }
}

/// Synchronous round trip for DylibLoaded (D-35). Best-effort: caller logs
/// failure but does NOT fail-closed (the wrapped command's main() runs even if
/// this times out — the daemon's gap-detector then records
/// `UnknownInjectionFailure`).
pub fn send_dylib_loaded_sync(
    audit_token: AuditTokenWire,
    timeout_ms: u64,
) -> Result<(), IpcClientError> {
    let ev = DylibLoaded {
        schema_version: IPC_SCHEMA_V2,
        audit_token,
    };
    let ack: DylibLoadedAck = send_tagged_and_recv_ack(TAG_DYLIB_LOADED, &ev, timeout_ms)?;
    match ack {
        DylibLoadedAck::Ok { .. } => Ok(()),
        DylibLoadedAck::Err { message, .. } => Err(IpcClientError::DaemonRejected(message)),
    }
}

/// Synchronous Resolve round-trip (gap-closure 02-08, D-42 replacement).
///
/// Sends a `Resolve { host, port }` request (tag 0x06) to the daemon and
/// returns the decoded list of resolved sockaddr wire buffers on success.
///
/// Returns:
///   - `Ok(Vec<[u8; SOCKADDR_WIRE_LEN]>)` on `ResolveReply::Addresses`
///   - `Err(IpcClientError::DaemonRejected(msg))` on `ResolveReply::Deny` or `ResolveReply::Err`
///   - `Err(IpcClientError::NotConfigured)` if the daemon socket is not configured
///   - `Err(IpcClientError::Timeout)` if the round-trip exceeds `timeout_ms`
///
/// Called on the libc connect cache-miss path — guarded by the caller to run
/// at most MAX_RESOLVE_ATTEMPTS = 4 times per connect invocation.
pub fn send_resolve_sync(
    host: &str,
    port: u16,
    timeout_ms: u64,
) -> Result<Vec<[u8; SOCKADDR_WIRE_LEN]>, IpcClientError> {
    let req = Resolve {
        schema_version: IPC_SCHEMA_V2,
        host: host.to_string(),
        port,
    };
    let reply: ResolveReply = send_tagged_and_recv_ack(TAG_RESOLVE, &req, timeout_ms)?;
    match reply {
        ResolveReply::Addresses {
            schema_version,
            addrs,
        } => {
            if schema_version != IPC_SCHEMA_V2 {
                return Err(IpcClientError::Codec(format!(
                    "ResolveReply schema_version {schema_version} != IPC_SCHEMA_V2"
                )));
            }
            Ok(addrs)
        }
        ResolveReply::Deny { reason, .. } => Err(IpcClientError::DaemonRejected(reason)),
        ResolveReply::Err { message, .. } => Err(IpcClientError::DaemonRejected(message)),
    }
}

/// Best-effort round trip for EnvNotPropagatedGap (TREE-06 — gap-closure 02-09).
///
/// Like `send_dylib_loaded_sync` (D-35), this does NOT fail-closed — the
/// calling posix_spawn shadow continues regardless of the result. TREE-06 is
/// an informational gap detector, not enforcement.
///
/// Returns `Ok(())` on `EnvNotPropagatedGapAck::Ok`, `Err(DaemonRejected)` on
/// `Err`, and `Err(Timeout)` / `Err(NotConfigured)` on IPC failures.
pub fn send_env_not_propagated_gap_sync(
    parent: AuditTokenWire,
    child_binary_path: &[u8],
    detected_at_ms: u64,
    timeout_ms: u64,
) -> Result<(), IpcClientError> {
    let capped_len = child_binary_path
        .len()
        .min(guard_ipc::EnvNotPropagatedGap::MAX_TARGET_PATH);
    let ev = guard_ipc::EnvNotPropagatedGap::new(
        parent,
        child_binary_path[..capped_len].to_vec(),
        detected_at_ms,
    );
    let ack: guard_ipc::EnvNotPropagatedGapAck =
        send_tagged_and_recv_ack(TAG_ENV_NOT_PROPAGATED, &ev, timeout_ms)?;
    match ack {
        guard_ipc::EnvNotPropagatedGapAck::Ok { .. } => Ok(()),
        guard_ipc::EnvNotPropagatedGapAck::Err { message, .. } => {
            Err(IpcClientError::DaemonRejected(message))
        }
    }
}

/// Fire-and-forget deny notification (D-39). The denial has already been
/// enforced at the libc level — this IPC only provides forensic logging.
///
/// Uses a 50ms total timeout to avoid blocking the hot path. Silently
/// discards all errors: if the daemon is down, the denial still happened.
pub fn send_deny_notify(
    audit_token: AuditTokenWire,
    dest_host: Option<&str>,
    dest_port: u16,
    dest_ip: Option<&str>,
    source_surface: &str,
    source_kind: &str,
) {
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);
    let ev = DenyNotify {
        schema_version: IPC_SCHEMA_V4,
        audit_token,
        dest_host: dest_host.map(|s| s.to_string()),
        dest_port,
        dest_ip: dest_ip.map(|s| s.to_string()),
        source_surface: source_surface.to_string(),
        denied_at_ms: now_ms,
        source_kind: source_kind.to_string(),
    };
    let _ = send_tagged_and_recv_ack::<DenyNotify, DenyNotifyAck>(TAG_DENY_NOTIFY, &ev, 50);
}

/// Fire-and-forget: tell the daemon a hardened-runtime exec was blocked.
pub fn send_exec_blocked(audit_token: AuditTokenWire, target_path: &[u8], reason: &str) {
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);
    let ev = ExecBlocked::new(audit_token, target_path, reason, now_ms);
    let _ = send_tagged_and_recv_ack::<ExecBlocked, ExecBlockedAck>(TAG_EXEC_BLOCKED, &ev, 50);
}

pub fn send_persistence_write(audit_token: AuditTokenWire, target_path: &[u8], category: &str) {
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);
    let ev = PersistenceWrite::new(audit_token, target_path, category, now_ms);
    let _ = send_tagged_and_recv_ack::<PersistenceWrite, PersistenceWriteAck>(
        TAG_PERSISTENCE_WRITE,
        &ev,
        50,
    );
}

// ---------------------------------------------------------------------------
// Fixed-size C-string buffer copy — no allocation, suitable for fork/exec hooks.
// ---------------------------------------------------------------------------

/// Copy the C-string at `p` into `buf`, stopping at the first NUL or at
/// `buf.len()` bytes. Returns the number of bytes copied (NOT including any
/// trailing NUL). Returns 0 on null pointer. Bytes in `buf` past the returned
/// length are NOT modified.
///
/// This helper is called from the exec shadows in `replace_exec.rs`. It must
/// be allocation-free and bounded — the caller passes a stack-allocated
/// `[u8; 1024]` so the copy is `O(min(strlen(p), 1024))` worst-case.
///
/// # Safety
/// `p` must either be null or point to a valid NUL-terminated C string.
pub fn copy_cstr_to_buf(p: *const c_char, buf: &mut [u8]) -> usize {
    if p.is_null() {
        return 0;
    }
    let mut n = 0usize;
    while n < buf.len() {
        // SAFETY: caller's invariant — p points to a NUL-terminated C string,
        // so reading bytes up to and including the first NUL is in-bounds.
        let b = unsafe { *p.add(n) as u8 };
        if b == 0 {
            break;
        }
        buf[n] = b;
        n += 1;
    }
    n
}
