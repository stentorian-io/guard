//! Phase 2 IPC handlers — PrepareSnapshot, TrustPolicy, Resolve.
//!
//! Plan 02-04 owns the Phase 2 fork/exec/dylib_loaded handlers (which live
//! inline in ipc_server.rs because they're small and tightly coupled to
//! peer-auth). The three handlers in this submodule are larger and have
//! independent unit tests, so they live as separate modules.

pub mod prepare_snapshot;
pub mod resolve;
pub mod trust_policy;
