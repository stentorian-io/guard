//! Peer authentication for the daemon's accept loop.
//!
//! Wraps `guard_ipc::transport::peer_identity`. v0.1 acceptable mitigation:
//! audit-token-only validation. v0.5 adds executable-path / codesign checks.

use guard_core::ProcessIdentity;
use guard_ipc::IpcError;
use guard_ipc::transport::peer_identity as ipc_peer_identity;
use std::os::unix::net::UnixStream;

/// Authenticate the peer connected to a daemon IPC stream.
///
/// # Errors
///
/// Returns IPC errors from the platform peer-identity lookup.
pub fn authenticate(stream: &UnixStream) -> Result<ProcessIdentity, IpcError> {
    ipc_peer_identity(stream)
}
