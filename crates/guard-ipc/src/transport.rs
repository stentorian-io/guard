//! Unix socket transport with OS-mediated peer authentication.
//!
//! v0.1 is request-reply only — synchronous blocking I/O is the right shape
//! (defer tokio-util until event-stream IPC is needed).
//!

use crate::error::IpcError;
use guard_core::{AuditToken, ProcessIdentity};
use std::os::unix::net::UnixStream;

/// Retrieve the peer process's kernel-sourced audit token from the connected
/// `UnixStream`.
///
/// SAFETY: this is the kernel-source side of `ProcessIdentity::from_kernel_token`.
/// The `audit_token` returned here is authoritative.
///
/// # Errors
///
/// Returns an IPC peer-authentication error if the OS peer lookup fails.
pub fn peer_audit_token(stream: &UnixStream) -> Result<AuditToken, IpcError> {
    guard_os::peer::peer_audit_token(stream).map_err(|e| IpcError::PeerAuth(e.to_string()))
}

/// Convenience: derive a `ProcessIdentity::Verified` for the peer.
///
/// # Errors
///
/// Returns an IPC peer-authentication error if the OS peer lookup fails.
pub fn peer_identity(stream: &UnixStream) -> Result<ProcessIdentity, IpcError> {
    guard_os::peer::peer_identity(stream).map_err(|e| IpcError::PeerAuth(e.to_string()))
}
