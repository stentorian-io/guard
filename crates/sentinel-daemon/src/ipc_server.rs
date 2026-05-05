//! Sync UnixListener accept loop.
//! One frame per connection; reply Ack/Err; close. No async runtime.
//!
//! BENIGN-EOF CONTRACT (T-01-05-09): plan 08's `probe_daemon_alive` is a
//! connect-only liveness probe — it opens a stream and drops it immediately,
//! sending no frame. From this side, `read_frame` returns
//! `IpcError::Io(e)` where `e.kind() == ErrorKind::UnexpectedEof`. We
//! recognize that case as a benign liveness probe: log at debug, mutate no
//! state (no tracked-root insert), write no Reply, close. This keeps the IPC
//! schema in plan 04 frozen at `RegisterRoot + Reply` (no `ProbeAlive`
//! wire variant needed) and lets the CLI prove daemon liveness using only
//! `connect_timeout` against the bound socket.

use crate::peer_auth::authenticate;
use crate::tracked::TrackedRoots;
use sentinel_ipc::frame::{read_frame, write_frame};
use sentinel_ipc::{IpcError, RegisterRoot, Reply};
use std::io::ErrorKind;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
use std::sync::Arc;
use tracing::{debug, error, info, warn};

pub struct IpcServer {
    listener: UnixListener,
    tracked: Arc<TrackedRoots>,
}

impl IpcServer {
    /// Bind a fresh listener at `socket_path`. Removes any stale socket file
    /// and sets mode 0600 on the new socket (so only the user can connect).
    pub fn bind(socket_path: &Path, tracked: Arc<TrackedRoots>) -> std::io::Result<Self> {
        let _ = std::fs::remove_file(socket_path);
        let listener = UnixListener::bind(socket_path)?;
        let mut perms = std::fs::metadata(socket_path)?.permissions();
        perms.set_mode(0o600);
        std::fs::set_permissions(socket_path, perms)?;
        Ok(Self { listener, tracked })
    }

    /// Accept one connection, handle one frame, return.
    /// Used by the integration test for a single round trip.
    pub fn accept_one(&self) -> std::io::Result<()> {
        let (stream, _) = self.listener.accept()?;
        Self::handle(stream, &self.tracked);
        Ok(())
    }

    /// Run forever, handling one connection at a time (single-threaded; Phase 2
    /// can switch to a thread-per-connection or pool when fork/exec event volume
    /// warrants it).
    pub fn run_forever(&self) -> std::io::Result<()> {
        loop {
            let (stream, _) = self.listener.accept()?;
            Self::handle(stream, &self.tracked);
        }
    }

    /// Return true if the IpcError is a benign EOF — peer connected then closed
    /// without sending a frame (the plan 08 connect-only liveness probe shape).
    fn is_benign_eof(e: &IpcError) -> bool {
        match e {
            IpcError::Io(io_err) => io_err.kind() == ErrorKind::UnexpectedEof,
            _ => false,
        }
    }

    fn handle(mut stream: UnixStream, tracked: &TrackedRoots) {
        let peer_id = match authenticate(&stream) {
            Ok(id) => id,
            Err(e) => {
                warn!(error = %e, "peer auth failed");
                let _ = write_frame(&mut stream, &Reply::err(format!("peer auth: {e}")));
                return;
            }
        };
        let key = match peer_id.as_policy_key() {
            Some(k) => *k,
            None => {
                warn!("peer authenticated as Unverified — refusing");
                let _ = write_frame(&mut stream, &Reply::err("peer not Verified"));
                return;
            }
        };
        let msg: RegisterRoot = match read_frame(&mut stream) {
            Ok(m) => m,
            Err(e) if Self::is_benign_eof(&e) => {
                // Connect-only liveness probe (plan 08 `probe_daemon_alive`).
                // Authenticated peer connected then closed without sending a
                // frame. No state change, no Reply written. T-01-05-09.
                debug!(
                    peer_pid = key.val[5],
                    "benign liveness probe (connect+EOF, no frame); no state change"
                );
                return;
            }
            Err(e) => {
                warn!(error = %e, "failed to read RegisterRoot");
                let _ = write_frame(&mut stream, &Reply::err(format!("frame: {e}")));
                return;
            }
        };
        // Trust the kernel-sourced audit token (key), NOT the wire-claimed one
        // (msg.audit_token). This is the ENF-08 invariant at the IPC boundary.
        let inserted = tracked.insert(key);
        let wire_pid = msg.audit_token.val[5];
        let kernel_pid = key.val[5];
        if wire_pid != kernel_pid {
            warn!(
                wire_pid,
                kernel_pid,
                "wire-claimed audit token disagrees with kernel-sourced; trusting kernel (T-01-04-03 mitigation)"
            );
        }
        info!(
            pid = kernel_pid,
            pidversion = key.val[7],
            inserted,
            "registered tracked root"
        );
        if let Err(e) = write_frame(&mut stream, &Reply::ack()) {
            error!(error = %e, "failed to send Ack");
        }
    }
}
