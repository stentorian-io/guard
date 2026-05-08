//! Phase 2 IPC handlers — PrepareSnapshot, TrustPolicy, Resolve.
//! Phase 3 plan 03-08 additions — Status, InsertUserRule, ReadInstallArtifacts, BaselineCommit.
//!
//! Plan 02-04 owns the Phase 2 fork/exec/dylib_loaded handlers (which live
//! inline in ipc_server.rs because they're small and tightly coupled to
//! peer-auth). The handlers in this submodule are larger and have
//! independent unit tests, so they live as separate modules.

pub mod baseline_commit;
pub mod delete_install_artifacts;
pub mod insert_user_rule;
pub mod is_trusted;
pub mod list_rules;
pub mod list_trust;
pub mod prepare_snapshot;
pub mod prompt_channel;
pub mod read_install_artifacts;
pub mod resolve;
pub mod status;
pub mod trust_policy;
