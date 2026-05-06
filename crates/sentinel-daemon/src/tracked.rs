//! Process-tree supervisor (TREE-03/04/05/06).
//!
//! Phase 1 used `TrackedRoots` (HashSet of AuditToken) for the simple
//! "is this process a tracked root?" question. Phase 2 grows into a full
//! tree: nodes are keyed by AuditToken (NOT pid — TREE-05 reparenting
//! requires a stable identity), each carries a parent link + a copied
//! `tracked_root` field set at fork time and immutable thereafter.
//!
//! Migration: ipc_server.rs (Task 4) is updated to call `insert_root`
//! instead of `insert`. The Phase 1 `TrackedRoots` type is removed.

use sentinel_core::AuditToken;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::RwLock;

#[derive(Debug, Clone)]
pub struct ProcessNode {
    pub audit_token: AuditToken,
    /// None for tracked-roots; Some(parent) for children.
    pub parent_audit_token: Option<AuditToken>,
    /// The original `sentinel run` root this node descends from. Set at fork
    /// time (or insert_root for the root itself) and NEVER changed afterwards
    /// — TREE-05: surviving reparenting means surviving ppid changes; the
    /// `tracked_root` field is the immutable view of "which sentinel run does
    /// this process belong to."
    pub tracked_root: AuditToken,
    pub run_uuid: String,
    pub binary_path: String,
    pub coverage_gap: Option<CoverageGap>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CoverageGap {
    /// csops pre-check was hardened AND DylibLoaded never arrived (D-34).
    ConfirmedHardened { binary_path: String, detected_at_ms: u64 },
    /// csops pre-check was NOT hardened but DylibLoaded never arrived — DYLD
    /// env var was lost (e.g. via `setsid`+ explicit env-clearing posix_spawn).
    UnknownInjectionFailure { binary_path: String, detected_at_ms: u64 },
    /// Future use: explicit env-not-propagated detection (TREE-06 polish path).
    EnvNotPropagated { binary_path: String, detected_at_ms: u64 },
}

#[derive(Debug, Clone)]
pub struct RunRecord {
    pub run_uuid: String,
    pub tracked_root: AuditToken,
    pub snapshot_path: PathBuf,
    pub manifest_path: PathBuf,
}

#[derive(Default)]
pub struct ProcessTree {
    nodes: RwLock<HashMap<AuditToken, ProcessNode>>,
    runs: RwLock<HashMap<String, RunRecord>>,
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
    pub fn insert_root(&self, audit_token: AuditToken, run_uuid: String, binary_path: String) -> bool {
        let mut g = self.nodes.write().expect("process_tree nodes write");
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
        };
        g.insert(audit_token, node);
        true
    }

    pub fn record_fork(
        &self,
        parent_audit_token: AuditToken,
        child_audit_token: AuditToken,
    ) -> Result<(), TreeError> {
        let mut g = self.nodes.write().expect("process_tree nodes write");
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
        };
        g.insert(child_audit_token, child);
        Ok(())
    }

    pub fn record_exec(
        &self,
        audit_token: AuditToken,
        binary_path: String,
    ) -> Result<(), TreeError> {
        let mut g = self.nodes.write().expect("process_tree nodes write");
        let node = g.get_mut(&audit_token).ok_or(TreeError::NodeNotFound)?;
        node.binary_path = binary_path;
        Ok(())
    }

    pub fn set_coverage_gap(
        &self,
        audit_token: AuditToken,
        gap: CoverageGap,
    ) -> Result<(), TreeError> {
        let mut g = self.nodes.write().expect("process_tree nodes write");
        let node = g.get_mut(&audit_token).ok_or(TreeError::NodeNotFound)?;
        node.coverage_gap = Some(gap);
        Ok(())
    }

    pub fn get_node(&self, audit_token: &AuditToken) -> Option<ProcessNode> {
        self.nodes.read().expect("process_tree nodes read").get(audit_token).cloned()
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
        self.nodes.read().expect("process_tree nodes read").len()
    }

    // --- run records ---

    pub fn insert_run(&self, run: RunRecord) {
        let mut g = self.runs.write().expect("process_tree runs write");
        g.insert(run.run_uuid.clone(), run);
    }

    pub fn remove_run(&self, run_uuid: &str) -> Option<RunRecord> {
        self.runs.write().expect("process_tree runs write").remove(run_uuid)
    }

    pub fn get_run(&self, run_uuid: &str) -> Option<RunRecord> {
        self.runs.read().expect("process_tree runs read").get(run_uuid).cloned()
    }

    pub fn runs_len(&self) -> usize {
        self.runs.read().expect("process_tree runs read").len()
    }
}

// ---------------------------------------------------------------------------
// TRANSITIONAL: `TrackedRoots` shim — preserves the Phase 1 ipc_server.rs
// surface (insert/contains/len/is_empty over a HashSet<AuditToken>) so the
// crate compiles incrementally between Task 1 and Task 4. Task 4 replaces
// ipc_server.rs and removes both `TrackedRoots` and the `tests/ipc_server_tests.rs`
// fixture that consumes it.
// ---------------------------------------------------------------------------

use std::collections::HashSet;
use std::sync::Mutex;

#[derive(Default)]
pub struct TrackedRoots {
    inner: Mutex<HashSet<AuditToken>>,
}

impl TrackedRoots {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(&self, token: AuditToken) -> bool {
        self.inner.lock().expect("tracked roots mutex").insert(token)
    }

    pub fn contains(&self, token: &AuditToken) -> bool {
        self.inner.lock().expect("tracked roots mutex").contains(token)
    }

    pub fn len(&self) -> usize {
        self.inner.lock().expect("tracked roots mutex").len()
    }

    pub fn is_empty(&self) -> bool {
        self.inner.lock().expect("tracked roots mutex").is_empty()
    }
}
