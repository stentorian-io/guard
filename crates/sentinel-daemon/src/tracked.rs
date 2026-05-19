//! Process-tree supervisor (TREE-03/04/05/06).
//!
//! v0.1 used `TrackedRoots` (HashSet of AuditToken) for the simple
//! "is this process a tracked root?" question. v0.2 grows into a full
//! tree: nodes are keyed by AuditToken (NOT pid — TREE-05 reparenting
//! requires a stable identity), each carries a parent link + a copied
//! `tracked_root` field set at fork time and immutable thereafter.
//!
//! Migration: ipc_server.rs (Task 4) is updated to call `insert_root`
//! instead of `insert`. The v0.1 `TrackedRoots` type is removed.

use crossbeam_channel::Sender;
use sentinel_core::AuditToken;
use sentinel_ipc::PromptRequest;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::RwLock;

#[derive(Debug, Clone)]
pub struct ProcessNode {
    pub audit_token: AuditToken,
    /// None for tracked-roots; Some(parent) for children.
    pub parent_audit_token: Option<AuditToken>,
    /// The original `sentinel wrap` root this node descends from. Set at fork
    /// time (or insert_root for the root itself) and NEVER changed afterwards
    /// — TREE-05: surviving reparenting means surviving ppid changes; the
    /// `tracked_root` field is the immutable view of "which sentinel wrap does
    /// this process belong to."
    pub tracked_root: AuditToken,
    pub run_uuid: String,
    pub binary_path: String,
    pub coverage_gap: Option<CoverageGap>,
    /// v0.3: PM env subset captured from ExecEvent V3.
    /// None until an ExecEvent V3 with non-empty pm_env arrives for this node.
    pub pm_env_snapshot: Option<Vec<(String, String)>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CoverageGap {
    /// csops pre-check was hardened AND DylibLoaded never arrived.
    ConfirmedHardened {
        binary_path: String,
        detected_at_ms: u64,
    },
    /// csops pre-check was NOT hardened but DylibLoaded never arrived — DYLD
    /// env var was lost (e.g. via `setsid`+ explicit env-clearing posix_spawn).
    UnknownInjectionFailure {
        binary_path: String,
        detected_at_ms: u64,
    },
    /// TREE-06: parent's posix_spawn was called with envp missing one or
    /// more of {DYLD_INSERT_LIBRARIES, SENTINEL_DAEMON_SOCKET,
    /// SENTINEL_SNAPSHOT_MANIFEST}. The child cannot inherit dylib
    /// injection. Detected by the dylib's posix_spawn shadow PRE-SPAWN.
    /// Recorded on the PARENT's ProcessNode (gap-closure 02-09).
    EnvNotPropagated {
        binary_path: String,
        detected_at_ms: u64,
    },
}

#[derive(Debug, Clone)]
pub struct RunRecord {
    pub run_uuid: String,
    pub tracked_root: AuditToken,
    pub snapshot_path: PathBuf,
    pub manifest_path: PathBuf,
    /// v0.3: true if the CLI that initiated this run is connected
    /// to a TTY (affects interactive prompt display).
    pub is_tty: bool,
    /// v0.3: true if this run was started with --baseline-mode
    /// (learn-mode: observe and record, but don't block).
    pub baseline_mode: bool,
}

#[derive(Default)]
pub struct ProcessTree {
    nodes: RwLock<HashMap<AuditToken, ProcessNode>>,
    runs: RwLock<HashMap<String, RunRecord>>,
    /// v0.3: long-lived prompt-channel senders keyed by run_uuid.
    /// Sender<PromptRequest> does not implement Clone cleanly into RunRecord
    /// (it would require RunRecord to become non-Clone), so it lives in a
    /// parallel registry — per RESEARCH.md guidance.
    prompt_channels: RwLock<HashMap<String, Sender<PromptRequest>>>,
}

#[derive(Debug, thiserror::Error)]
pub enum TreeError {
    #[error("parent audit_token not in tree")]
    ParentNotFound,
    #[error("audit_token not in tree")]
    NodeNotFound,
}

impl ProcessTree {
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert a tracked-root node. Idempotent: returns false if already present.
    pub fn insert_root(
        &self,
        audit_token: AuditToken,
        run_uuid: String,
        binary_path: String,
    ) -> bool {
        // WARNING-03: tolerate poison so a worker panic in one handler does
        // not poison the daemon-wide process tree forever.
        let mut g = self.nodes.write().unwrap_or_else(|p| p.into_inner());
        if g.contains_key(&audit_token) {
            return false;
        }
        let node = ProcessNode {
            audit_token,
            parent_audit_token: None,
            tracked_root: audit_token,
            run_uuid,
            binary_path,
            coverage_gap: None,
            pm_env_snapshot: None,
        };
        g.insert(audit_token, node);
        true
    }

    pub fn record_fork(
        &self,
        parent_audit_token: AuditToken,
        child_audit_token: AuditToken,
    ) -> Result<(), TreeError> {
        // WARNING-03: tolerate poison so a worker panic in one handler does
        // not poison the daemon-wide process tree forever.
        let mut g = self.nodes.write().unwrap_or_else(|p| p.into_inner());
        let parent = g
            .get(&parent_audit_token)
            .ok_or(TreeError::ParentNotFound)?
            .clone();
        let child = ProcessNode {
            audit_token: child_audit_token,
            parent_audit_token: Some(parent_audit_token),
            // TREE-05: child inherits the ORIGINAL tracked_root from the parent
            // (which itself inherited from its parent, etc.) — chain leads back
            // to the sentinel-run root.
            tracked_root: parent.tracked_root,
            run_uuid: parent.run_uuid.clone(),
            binary_path: String::new(), // filled in on subsequent ExecEvent
            coverage_gap: None,
            pm_env_snapshot: None,
        };
        g.insert(child_audit_token, child);
        Ok(())
    }

    pub fn record_exec(
        &self,
        audit_token: AuditToken,
        binary_path: String,
    ) -> Result<(), TreeError> {
        // WARNING-03: tolerate poison so a worker panic in one handler does
        // not poison the daemon-wide process tree forever.
        let mut g = self.nodes.write().unwrap_or_else(|p| p.into_inner());
        let node = g.get_mut(&audit_token).ok_or(TreeError::NodeNotFound)?;
        node.binary_path = binary_path;
        Ok(())
    }

    pub fn set_coverage_gap(
        &self,
        audit_token: AuditToken,
        gap: CoverageGap,
    ) -> Result<(), TreeError> {
        // WARNING-03: tolerate poison so a worker panic in one handler does
        // not poison the daemon-wide process tree forever.
        let mut g = self.nodes.write().unwrap_or_else(|p| p.into_inner());
        let node = g.get_mut(&audit_token).ok_or(TreeError::NodeNotFound)?;
        node.coverage_gap = Some(gap);
        Ok(())
    }

    pub fn get_node(&self, audit_token: &AuditToken) -> Option<ProcessNode> {
        self.nodes
            .read()
            .unwrap_or_else(|p| p.into_inner())
            .get(audit_token)
            .cloned()
    }

    // --- v0.3: pm_env snapshot ---

    /// Store the filtered PM env snapshot on a ProcessNode identified by audit_token.
    /// No-op if the audit_token is not in the tree (untracked peer race — safe to ignore).
    pub fn set_pm_env_snapshot(&self, audit_token: &AuditToken, pm_env: Vec<(String, String)>) {
        let mut g = self.nodes.write().unwrap_or_else(|p| p.into_inner());
        if let Some(node) = g.get_mut(audit_token) {
            node.pm_env_snapshot = Some(pm_env);
        }
    }

    // --- v0.3: run field setters ---

    /// Update is_tty on a RunRecord identified by run_uuid.
    /// No-op if the run_uuid is not in the map.
    pub fn set_run_is_tty(&self, run_uuid: &str, is_tty: bool) {
        let mut g = self.runs.write().unwrap_or_else(|p| p.into_inner());
        if let Some(rec) = g.get_mut(run_uuid) {
            rec.is_tty = is_tty;
        }
    }

    /// Update baseline_mode on a RunRecord identified by run_uuid.
    /// No-op if the run_uuid is not in the map.
    pub fn set_run_baseline_mode(&self, run_uuid: &str, baseline_mode: bool) {
        let mut g = self.runs.write().unwrap_or_else(|p| p.into_inner());
        if let Some(rec) = g.get_mut(run_uuid) {
            rec.baseline_mode = baseline_mode;
        }
    }

    /// Bind a tracked root to an existing run after the CLI has spawned the
    /// wrapped child and obtained its kernel audit token.
    pub fn bind_run_root(&self, run_uuid: &str, tracked_root: AuditToken) {
        {
            let mut runs = self.runs.write().unwrap_or_else(|p| p.into_inner());
            if let Some(rec) = runs.get_mut(run_uuid) {
                rec.tracked_root = tracked_root;
            }
        }
        let mut nodes = self.nodes.write().unwrap_or_else(|p| p.into_inner());
        if let Some(node) = nodes.get_mut(&tracked_root) {
            node.run_uuid = run_uuid.to_string();
            node.tracked_root = tracked_root;
        }
    }

    /// Return all active RunRecords (used by StatusReply handler).
    pub fn list_runs(&self) -> Vec<RunRecord> {
        let g = self.runs.read().unwrap_or_else(|p| p.into_inner());
        g.values().cloned().collect()
    }

    // --- v0.3: prompt-channel registry ---

    /// Register a long-lived prompt-channel Sender for the given run_uuid.
    /// Called by the PromptChannelInit handler.
    pub fn set_prompt_channel(&self, run_uuid: &str, sender: Sender<PromptRequest>) {
        let mut g = self
            .prompt_channels
            .write()
            .unwrap_or_else(|p| p.into_inner());
        g.insert(run_uuid.to_string(), sender);
    }

    /// Remove and return the prompt-channel Sender for the given run_uuid.
    /// Called when the prompt channel connection closes or the run ends.
    pub fn take_prompt_channel(&self, run_uuid: &str) -> Option<Sender<PromptRequest>> {
        let mut g = self
            .prompt_channels
            .write()
            .unwrap_or_else(|p| p.into_inner());
        g.remove(run_uuid)
    }

    /// Clone and return the prompt-channel Sender for the given run_uuid.
    /// Returns None if no channel is registered for this run.
    /// Sender is cheap to clone (Arc internals).
    pub fn get_prompt_channel(&self, run_uuid: &str) -> Option<Sender<PromptRequest>> {
        let g = self
            .prompt_channels
            .read()
            .unwrap_or_else(|p| p.into_inner());
        g.get(run_uuid).cloned()
    }

    /// Return the number of active long-lived prompt channels.
    /// Used by ipc_server.rs's R-05 cap gate.
    pub fn prompt_channels_len(&self) -> usize {
        let g = self
            .prompt_channels
            .read()
            .unwrap_or_else(|p| p.into_inner());
        g.len()
    }

    pub fn is_tracked(&self, audit_token: &AuditToken) -> bool {
        self.nodes
            .read()
            .expect("process_tree nodes read")
            .contains_key(audit_token)
    }

    pub fn is_tracked_root(&self, audit_token: &AuditToken) -> bool {
        let g = self.nodes.read().expect("process_tree nodes read");
        g.get(audit_token)
            .map(|n| n.parent_audit_token.is_none() && n.tracked_root == *audit_token)
            .unwrap_or(false)
    }

    pub fn nodes_len(&self) -> usize {
        self.nodes.read().unwrap_or_else(|p| p.into_inner()).len()
    }

    /// Return the first node whose audit_token has val[5] == pid.
    /// Used by unit tests that need to find a node by pid without knowing
    /// the full 8-field kernel audit token.
    pub fn find_node_by_pid(&self, pid: u32) -> Option<ProcessNode> {
        let g = self.nodes.read().unwrap_or_else(|p| p.into_inner());
        g.values().find(|n| n.audit_token.val[5] == pid).cloned()
    }

    // --- run records ---

    pub fn insert_run(&self, run: RunRecord) {
        let mut g = self.runs.write().unwrap_or_else(|p| p.into_inner());
        g.insert(run.run_uuid.clone(), run);
    }

    pub fn remove_run(&self, run_uuid: &str) -> Option<RunRecord> {
        self.runs
            .write()
            .unwrap_or_else(|p| p.into_inner())
            .remove(run_uuid)
    }

    pub fn get_run(&self, run_uuid: &str) -> Option<RunRecord> {
        self.runs
            .read()
            .unwrap_or_else(|p| p.into_inner())
            .get(run_uuid)
            .cloned()
    }

    pub fn runs_len(&self) -> usize {
        self.runs.read().unwrap_or_else(|p| p.into_inner()).len()
    }

    /// Return (pid, pidversion) pairs for all tracked nodes.
    /// Used by the persistence watcher for process attribution.
    pub fn list_tracked_pids(&self) -> Vec<(u32, u32)> {
        let g = self.nodes.read().unwrap_or_else(|p| p.into_inner());
        g.values()
            .map(|n| (n.audit_token.val[5], n.audit_token.val[7]))
            .collect()
    }
}
