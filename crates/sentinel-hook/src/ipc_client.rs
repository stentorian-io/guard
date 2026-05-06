//! Dylib-side blocking IPC client for ForkEvent / ExecEvent / DylibLoaded.
//!
//! D-31: synchronous — the calling hook blocks until the daemon Acks.
//! D-33: fail-closed-on-timeout for fork events (caller kills child + EAGAIN).
//!
//! Socket path: read once at ctor time from SENTINEL_DAEMON_SOCKET env var via
//! libc::getenv (matches Phase 1 snapshot.rs pattern — keeps ctor allocation
//! minimal and avoids std::env::var which allocates per call).
//!
//! Wire shape: each message is a `tag byte (0x03..=0x05) + length-prefixed CBOR
//! body`. The daemon's first-byte-peek dispatcher (plan 02-04) routes the tag
//! to the matching handler. The handler responds with the same tag echoed
//! followed by a length-prefixed CBOR ack body.

use core::ffi::{c_char, CStr};
use sentinel_ipc::frame::{read_frame, write_frame};
use sentinel_ipc::{
    AuditTokenWire, DylibLoaded, DylibLoadedAck, ExecAck, ExecEvent, ForkAck, ForkEvent,
    IPC_SCHEMA_V2,
};
use socket2::{Domain, SockAddr, Socket, Type};
use std::io::{Read, Write};
use std::os::unix::io::{FromRawFd, IntoRawFd};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use std::time::Duration;

// Tag bytes — must match plan 02-04's MessageTag values exactly.
pub(crate) const TAG_FORK_EVENT: u8 = 0x03;
pub(crate) const TAG_EXEC_EVENT: u8 = 0x04;
pub(crate) const TAG_DYLIB_LOADED: u8 = 0x05;

static DAEMON_SOCKET_PATH: OnceLock<Option<PathBuf>> = OnceLock::new();

#[derive(Debug)]
pub enum IpcClientError {
    /// SENTINEL_DAEMON_SOCKET env var unset (e.g. unit tests, or dylib loaded
    /// outside `sentinel run`). Caller treats this as "no IPC available".
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
            IpcClientError::NotConfigured => write!(f, "ipc-client: SENTINEL_DAEMON_SOCKET unset"),
            IpcClientError::Timeout => write!(f, "ipc-client: timeout"),
            IpcClientError::Io(e) => write!(f, "ipc-client: io: {e}"),
            IpcClientError::DaemonRejected(m) => write!(f, "ipc-client: daemon-rejected: {m}"),
            IpcClientError::Codec(m) => write!(f, "ipc-client: codec: {m}"),
        }
    }
}

/// Read SENTINEL_DAEMON_SOCKET via libc::getenv (allocation-free until found).
/// Idempotent — subsequent calls are no-ops. Called once from the dylib ctor.
pub fn cache_daemon_socket_from_env() {
    DAEMON_SOCKET_PATH.get_or_init(|| {
        // SAFETY: ctor runs pre-main, single-threaded; getenv pointer stable.
        unsafe {
            let p = libc::getenv(c"SENTINEL_DAEMON_SOCKET".as_ptr());
            if p.is_null() {
                return None;
            }
            let s = CStr::from_ptr(p).to_string_lossy();
            if s.is_empty() {
                return None;
            }
            Some(PathBuf::from(s.as_ref()))
        }
    });
}

/// Returns the cached socket path, if configured.
pub fn daemon_socket_path() -> Option<&'static Path> {
    DAEMON_SOCKET_PATH.get().and_then(|o| o.as_deref())
}

fn connect_with_timeout(sock: &Path, total_ms: u64) -> Result<UnixStream, IpcClientError> {
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
    let fd = socket.into_raw_fd();
    // SAFETY: we own the fd; from_raw_fd takes ownership.
    Ok(unsafe { UnixStream::from_raw_fd(fd) })
}

fn map_io_to_timeout(e: std::io::Error) -> IpcClientError {
    if e.kind() == std::io::ErrorKind::TimedOut || e.kind() == std::io::ErrorKind::WouldBlock {
        IpcClientError::Timeout
    } else {
        IpcClientError::Io(e)
    }
}

fn send_tagged_and_recv_ack<Req, Ack>(
    tag: u8,
    msg: &Req,
    timeout_ms: u64,
) -> Result<Ack, IpcClientError>
where
    Req: serde::Serialize,
    Ack: serde::de::DeserializeOwned,
{
    let sock = daemon_socket_path().ok_or(IpcClientError::NotConfigured)?;
    let mut stream = connect_with_timeout(sock, timeout_ms)?;
    // Tag byte first.
    stream.write_all(&[tag]).map_err(map_io_to_timeout)?;
    // Length-prefixed CBOR body.
    write_frame(&mut stream, msg).map_err(|e| IpcClientError::Codec(e.to_string()))?;
    // Read the response: tag byte (echoed by daemon) + length-prefixed body.
    let mut tag_back = [0u8; 1];
    stream.read_exact(&mut tag_back).map_err(map_io_to_timeout)?;
    if tag_back[0] != tag {
        return Err(IpcClientError::Codec(format!(
            "tag mismatch: sent 0x{tag:02x}, got 0x{:02x}",
            tag_back[0]
        )));
    }
    let ack: Ack = read_frame(&mut stream).map_err(|e| IpcClientError::Codec(e.to_string()))?;
    Ok(ack)
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
pub fn send_exec_event_sync(
    audit_token: AuditTokenWire,
    target_path: &[u8],
    target_path_len: usize,
    timeout_ms: u64,
) -> Result<(), IpcClientError> {
    let len = target_path_len
        .min(target_path.len())
        .min(ExecEvent::MAX_TARGET_PATH);
    let ev = ExecEvent {
        schema_version: IPC_SCHEMA_V2,
        audit_token,
        target_path: target_path[..len].to_vec(),
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
