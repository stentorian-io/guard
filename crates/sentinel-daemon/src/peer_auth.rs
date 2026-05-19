//! Peer authentication for the daemon's accept loop.
//!
//! Wraps sentinel_ipc::transport::peer_identity. v0.1 acceptable mitigation:
//! audit-token-only validation. v0.5 adds executable-path / codesign checks.

use sentinel_core::ProcessIdentity;
use sentinel_ipc::transport::peer_identity as ipc_peer_identity;
use sentinel_ipc::IpcError;
use std::os::unix::net::UnixStream;

pub fn authenticate(stream: &UnixStream) -> Result<ProcessIdentity, IpcError> {
    ipc_peer_identity(stream)
}
