//! Connect to the daemon socket, send messages, await Replies.
//!
//! ISS-08 remediation: explicit 5-second connect timeout (rather than relying
//! on the OS-default connect(2) timeout, which is implementation-defined on
//! macOS for unix-domain sockets). We achieve this with the documented Rust
//! pattern: build a non-blocking socket via the `socket2` crate (already in
//! the workspace), call `connect_timeout`, then convert to a blocking
//! `UnixStream` for the read/write phase.

use crate::CliError;
use sentinel_core::AuditToken;
use sentinel_ipc::frame::{read_frame, write_frame};
use sentinel_ipc::{
    PrepareSnapshot, RegisterRoot, Reply, SnapshotReply, TrustPolicy, TrustPolicyReply,
};
use socket2::{Domain, SockAddr, Socket, Type};
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::time::Duration;

// Tag bytes — must match plan 02-04's MessageTag values exactly. The dylib
// uses the same values in `sentinel_hook::ipc_client`.
const TAG_PREPARE_SNAPSHOT: u8 = 0x02;
const TAG_TRUST_POLICY: u8 = 0x07;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const READ_TIMEOUT: Duration = Duration::from_secs(5);
const WRITE_TIMEOUT: Duration = Duration::from_secs(5);

/// Connect to the daemon socket with an explicit 5s connect timeout. Returns
/// a blocking `UnixStream` on success. ISS-08: the prior implementation used
/// `UnixStream::connect` which has no documented timeout and could block
/// indefinitely on certain Darwin states.
fn connect_with_timeout(sock: &Path) -> Result<UnixStream, CliError> {
    let addr = SockAddr::unix(sock).map_err(|e| {
        CliError::DaemonUnreachable(format!("sockaddr({}): {e}", sock.display()))
    })?;
    let socket = Socket::new(Domain::UNIX, Type::STREAM, None)
        .map_err(|e| CliError::DaemonUnreachable(format!("socket: {e}")))?;
    socket
        .connect_timeout(&addr, CONNECT_TIMEOUT)
        .map_err(|e| {
            CliError::DaemonUnreachable(format!("connect({}): {e}", sock.display()))
        })?;
    socket.set_read_timeout(Some(READ_TIMEOUT)).ok();
    socket.set_write_timeout(Some(WRITE_TIMEOUT)).ok();
    // Convert socket2::Socket → std::net::TcpStream-like → UnixStream.
    // socket2::Socket implements Into<std::net::TcpStream>... actually it implements
    // From<Socket> for std::os::unix::net::UnixStream via Into<std::fs::File> on Unix.
    // We use the os-level RawFd conversion.
    use std::os::unix::io::FromRawFd;
    use std::os::unix::io::IntoRawFd;
    let fd = socket.into_raw_fd();
    // SAFETY: fd is a valid open Unix domain socket descriptor we own.
    let stream = unsafe { UnixStream::from_raw_fd(fd) };
    Ok(stream)
}

/// ISS-08 remediation: connect-only liveness probe sent BEFORE spawning the
/// wrapped child. If the daemon is unreachable, the CLI exits 70 (EX_SOFTWARE)
/// without having forked an unprotected child — keeping T-01-08-06's promise.
///
/// Why connect-only (no frame sent):
///   - The socket file at `sock` is bound by the daemon (`UnixListener::bind`
///     in plan 05 task 2). A non-running daemon yields ECONNREFUSED or ENOENT,
///     so a successful `connect_timeout` IS sufficient liveness evidence.
///   - Sending a frame would require defining a new wire message type
///     (avoided: keeps the IPC schema minimal and forward-compatible — no new
///     enum variants in plan 04's messages.rs are needed).
///   - Plan 05 task 2's `ipc_server::handle` tolerates the resulting EOF on
///     `read_frame` as a benign liveness probe (no state change, no panic,
///     idle log line at debug level).
///
/// The stream is dropped immediately on success; the daemon's `accept()` sees
/// a connect+immediate-close, which is the documented benign liveness path.
pub fn probe_daemon_alive(sock: &Path) -> Result<(), CliError> {
    let _stream = connect_with_timeout(sock)?;
    // Stream dropped here; the daemon will see EOF on its first read_frame
    // and treat it as a benign liveness check (plan 05 task 2 contract).
    Ok(())
}

pub fn register_root_with_daemon(sock: &Path, token: AuditToken) -> Result<(), CliError> {
    let mut stream = connect_with_timeout(sock)?;
    let msg = RegisterRoot::new(token);
    write_frame(&mut stream, &msg)?;
    let reply: Reply = read_frame(&mut stream)?;
    match reply {
        Reply::Ack { .. } => Ok(()),
        Reply::Err { message, .. } => {
            Err(CliError::DaemonUnreachable(format!("daemon: {message}")))
        }
    }
}

/// Send a Phase 2 tagged frame: `[1-byte tag][4-byte BE length][CBOR body]`,
/// then read the daemon's tag-echoed reply: `[1-byte tag][4-byte BE length][CBOR body]`.
///
/// Wire shape symmetry with:
///   - daemon-side:  `crates/sentinel-daemon/src/ipc_server.rs::write_tagged`
///   - dylib-side:   `crates/sentinel-hook/src/ipc_client.rs::send_tagged_and_recv_ack`
fn send_tagged_request<Req, ReplyT>(
    sock: &Path,
    tag: u8,
    req: &Req,
) -> Result<ReplyT, CliError>
where
    Req: serde::Serialize,
    ReplyT: serde::de::DeserializeOwned,
{
    let mut stream = connect_with_timeout(sock)?;
    stream
        .write_all(&[tag])
        .map_err(|e| CliError::DaemonUnreachable(format!("tag write: {e}")))?;
    write_frame(&mut stream, req)
        .map_err(|e| CliError::DaemonUnreachable(format!("write frame: {e}")))?;
    let mut tag_back = [0u8; 1];
    stream
        .read_exact(&mut tag_back)
        .map_err(|e| CliError::DaemonUnreachable(format!("read tag echo: {e}")))?;
    if tag_back[0] != tag {
        return Err(CliError::DaemonUnreachable(format!(
            "tag mismatch: sent 0x{tag:02x}, got 0x{:02x}",
            tag_back[0]
        )));
    }
    let reply: ReplyT = read_frame(&mut stream)
        .map_err(|e| CliError::DaemonUnreachable(format!("read reply: {e}")))?;
    Ok(reply)
}

/// Phase 2 D-29: send `PrepareSnapshot { cwd }` BEFORE posix_spawn so the
/// daemon walks `cwd` for `.sentinel.toml`, merges curated YAML + SQLite + the
/// project policy, writes a per-run snapshot to `${state_dir}/runs/{uuid}.cbor`,
/// and returns the manifest path. The CLI then sets that manifest path as
/// `SENTINEL_SNAPSHOT_MANIFEST` in the wrapped child's envp so the dylib
/// loads the per-run policy.
pub fn prepare_snapshot(sock: &Path, cwd: &Path) -> Result<(PathBuf, String), CliError> {
    let req = PrepareSnapshot::new(cwd.display().to_string());
    let reply: SnapshotReply = send_tagged_request(sock, TAG_PREPARE_SNAPSHOT, &req)?;
    match reply {
        SnapshotReply::Ok {
            manifest_path,
            run_uuid,
            ..
        } => Ok((PathBuf::from(manifest_path), run_uuid)),
        SnapshotReply::Err { message, .. } => {
            Err(CliError::Other(format!("PrepareSnapshot: {message}")))
        }
    }
}

/// Phase 2 D-38: send `TrustPolicy { path, sha256 }` so the daemon inserts the
/// (path, sha256) tuple into `trusted_policy_files`. The daemon performs a
/// defense-in-depth re-hash of the file at handler time (T-02-06a-01) and
/// rejects on mismatch — the CLI's claimed sha256 is treated as a diagnostic
/// value, never trusted on its own.
pub fn trust_policy_request(sock: &Path, path: &str, sha256: &str) -> Result<(), CliError> {
    let req = TrustPolicy::new(path, sha256);
    let reply: TrustPolicyReply = send_tagged_request(sock, TAG_TRUST_POLICY, &req)?;
    match reply {
        TrustPolicyReply::Ok { .. } => Ok(()),
        TrustPolicyReply::Err { message, .. } => {
            Err(CliError::Other(format!("TrustPolicy: {message}")))
        }
    }
}
