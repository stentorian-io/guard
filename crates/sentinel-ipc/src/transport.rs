//! Unix socket transport with macOS-native peer audit-token authentication.
//!
//! v0.1 is request-reply only — synchronous blocking I/O is the right shape
//! (defer tokio-util until event-stream IPC is needed).
//!
//! Peer authentication uses `getsockopt(SOL_LOCAL, LOCAL_PEERTOKEN, ...)` —
//! never `SO_PEERCRED` (that's a Linux idiom and does not return audit tokens).

use crate::error::IpcError;
use core::ffi::c_void;
use sentinel_core::{AuditToken, ProcessIdentity};
use std::os::unix::io::AsRawFd;
use std::os::unix::net::UnixStream;

// macOS sys/un.h constants. Verified against SDK header by the Wave 0 spike (A1).
const SOL_LOCAL: libc::c_int = 0;
const LOCAL_PEERTOKEN: libc::c_int = 0x006;

/// Retrieve the peer process's kernel-sourced audit token from the connected
/// UnixStream.
///
/// SAFETY: this is the kernel-source side of `ProcessIdentity::from_kernel_token`.
/// The audit_token returned here is authoritative.
pub fn peer_audit_token(stream: &UnixStream) -> Result<AuditToken, IpcError> {
    let mut tok = AuditToken::synthetic([0; 8]);
    let mut len: libc::socklen_t = core::mem::size_of::<AuditToken>() as _;
    let r = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            SOL_LOCAL,
            LOCAL_PEERTOKEN,
            &mut tok as *mut AuditToken as *mut c_void,
            &mut len,
        )
    };
    if r < 0 {
        return Err(IpcError::PeerAuth(std::io::Error::last_os_error().to_string()));
    }
    if len as usize != core::mem::size_of::<AuditToken>() {
        return Err(IpcError::PeerAuth(format!(
            "LOCAL_PEERTOKEN returned unexpected length {len}"
        )));
    }
    Ok(tok)
}

/// Convenience: derive a `ProcessIdentity::Verified` for the peer.
///
/// The unsafe block here is the trust-boundary annotation: we are calling
/// `from_kernel_token` because `peer_audit_token` IS the kernel source.
pub fn peer_identity(stream: &UnixStream) -> Result<ProcessIdentity, IpcError> {
    let token = peer_audit_token(stream)?;
    // SAFETY: `token` came from getsockopt(SOL_LOCAL, LOCAL_PEERTOKEN, ...) which
    // is a kernel-blessed source.
    Ok(unsafe { ProcessIdentity::from_kernel_token(token) })
}
