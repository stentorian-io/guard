//! crates/guard-daemon/src/daemon_state.rs
//!
//! v0.3 — `DeferredResolveTable` re-exports.
//!
//! `DaemonState` itself lives in `ipc_server.rs` (where all the IPC handler
//! infrastructure is). This module provides public re-exports under the
//! `guard_daemon::daemon_state` path so integration tests can import
//! `DeferredResolveTable` and `DeferredEntry` without depending on the
//! internal `ipc_server` module path.

pub use crate::ipc_server::{DeferredEntry, DeferredResolveTable};
