//! v0.2 IPC handlers — PrepareSnapshot, Resolve.
//! v0.3 additions — Status, InsertUserRule, ReadInstallArtifacts, BaselineCommit.
//!
//! The v0.2 fork/exec/dylib_loaded handlers live
//! inline in ipc_server.rs because they're small and tightly coupled to
//! peer-auth). The handlers in this submodule are larger and have
//! independent unit tests, so they live as separate modules.

pub mod baseline_commit;
pub mod delete_install_artifacts;
pub mod insert_user_rule;
pub mod list_rules;
pub mod prepare_snapshot;
pub mod prompt_channel;
pub mod read_install_artifacts;
pub mod resolve;
pub mod status;
