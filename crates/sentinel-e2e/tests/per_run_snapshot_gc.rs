//! D-29 per-run snapshot lifecycle: gc_sweep removes stale entries.
//!
//! Three invariants the GC sweeper MUST hold:
//!   1. Orphan removal — files in runs/ with NO matching RunRecord (e.g. left
//!      over from a daemon restart) are removed.
//!   2. Live preservation — files whose RunRecord pid is alive are NOT removed.
//!   3. Dead-pid removal — files whose RunRecord pid is no longer alive are
//!      removed AND the RunRecord is dropped from the ProcessTree.
//!
//! These tests do NOT exercise the daemon's IPC path or the periodic timer;
//! they call `gc_sweep` directly. The periodic loop (`spawn_gc_thread`) is
//! a thin wrapper that calls `gc_sweep` every GC_INTERVAL_SECS and is exercised
//! implicitly when the daemon runs end-to-end.

use sentinel_core::AuditToken;
use sentinel_daemon::snapshot_gc::gc_sweep;
use sentinel_daemon::state_dir::{ensure_runs_dir, run_manifest_path, run_snapshot_path};
use sentinel_daemon::tracked::{ProcessTree, RunRecord};
use std::sync::Arc;
use tempfile::TempDir;

#[cfg_attr(not(target_os = "macos"), ignore)]
#[test]
fn gc_removes_orphan_snapshots() {
    let tmp = TempDir::new().unwrap();
    let state_dir = tmp.path().to_path_buf();
    ensure_runs_dir(&state_dir).unwrap();
    let tree = Arc::new(ProcessTree::new());

    // Plant an orphan: cbor + manifest with NO matching RunRecord.
    let orphan_uuid = "11111111-2222-3333-4444-555555555555";
    let snap_path = run_snapshot_path(&state_dir, orphan_uuid);
    let manifest_path = run_manifest_path(&state_dir, orphan_uuid);
    std::fs::write(&snap_path, b"orphan-snapshot-bytes").unwrap();
    std::fs::write(&manifest_path, b"orphan-manifest").unwrap();
    assert!(snap_path.exists());
    assert!(manifest_path.exists());

    gc_sweep(&state_dir, &tree);

    assert!(!snap_path.exists(), "orphan snapshot must be GC'd");
    assert!(!manifest_path.exists(), "orphan manifest must be GC'd");
}

#[cfg_attr(not(target_os = "macos"), ignore)]
#[test]
fn gc_preserves_live_snapshots() {
    let tmp = TempDir::new().unwrap();
    let state_dir = tmp.path().to_path_buf();
    ensure_runs_dir(&state_dir).unwrap();
    let tree = Arc::new(ProcessTree::new());

    // Plant a live entry: file + RunRecord pointing at the running test process.
    let live_uuid = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee";
    let snap_path = run_snapshot_path(&state_dir, live_uuid);
    let manifest_path = run_manifest_path(&state_dir, live_uuid);
    std::fs::write(&snap_path, b"live-snapshot-bytes").unwrap();
    std::fs::write(&manifest_path, b"live-manifest").unwrap();
    let my_pid = unsafe { libc::getpid() };
    let token = AuditToken { val: [0, 0, 0, 0, 0, my_pid as u32, 0, 0] };
    tree.insert_run(RunRecord {
        run_uuid: live_uuid.to_string(),
        tracked_root: token,
        snapshot_path: snap_path.clone(),
        manifest_path: manifest_path.clone(),
    });

    gc_sweep(&state_dir, &tree);

    assert!(snap_path.exists(), "live snapshot must NOT be GC'd");
    assert!(manifest_path.exists(), "live manifest must NOT be GC'd");
    assert!(tree.get_run(live_uuid).is_some(), "RunRecord preserved");
}

#[cfg_attr(not(target_os = "macos"), ignore)]
#[test]
fn gc_removes_dead_pid_snapshots() {
    let tmp = TempDir::new().unwrap();
    let state_dir = tmp.path().to_path_buf();
    ensure_runs_dir(&state_dir).unwrap();
    let tree = Arc::new(ProcessTree::new());

    // Plant: file + RunRecord pointing at a definitely-dead pid.
    let dead_uuid = "ffffffff-0000-1111-2222-333333333333";
    let snap_path = run_snapshot_path(&state_dir, dead_uuid);
    let manifest_path = run_manifest_path(&state_dir, dead_uuid);
    std::fs::write(&snap_path, b"x").unwrap();
    std::fs::write(&manifest_path, b"y").unwrap();
    // Pick a PID that is overwhelmingly unlikely to be alive.
    let dead_pid: u32 = 99_999_999;
    let token = AuditToken { val: [0, 0, 0, 0, 0, dead_pid, 0, 0] };
    tree.insert_run(RunRecord {
        run_uuid: dead_uuid.to_string(),
        tracked_root: token,
        snapshot_path: snap_path.clone(),
        manifest_path: manifest_path.clone(),
    });

    gc_sweep(&state_dir, &tree);

    assert!(!snap_path.exists(), "dead-pid snapshot must be GC'd");
    assert!(!manifest_path.exists(), "dead-pid manifest must be GC'd");
    assert!(tree.get_run(dead_uuid).is_none(), "RunRecord removed");
}

#[cfg_attr(not(target_os = "macos"), ignore)]
#[test]
fn gc_skips_runrecord_with_zero_pid_placeholder() {
    // PrepareSnapshot inserts RunRecord with placeholder zero AuditToken
    // (tracked_root not yet bound — RegisterRoot updates it later). The GC
    // MUST NOT remove these — they're in-flight, not stale.
    let tmp = TempDir::new().unwrap();
    let state_dir = tmp.path().to_path_buf();
    ensure_runs_dir(&state_dir).unwrap();
    let tree = Arc::new(ProcessTree::new());

    let pending_uuid = "00000000-1111-2222-3333-444444444444";
    let snap_path = run_snapshot_path(&state_dir, pending_uuid);
    let manifest_path = run_manifest_path(&state_dir, pending_uuid);
    std::fs::write(&snap_path, b"pending-snap").unwrap();
    std::fs::write(&manifest_path, b"pending-manifest").unwrap();
    let token = AuditToken { val: [0; 8] }; // placeholder
    tree.insert_run(RunRecord {
        run_uuid: pending_uuid.to_string(),
        tracked_root: token,
        snapshot_path: snap_path.clone(),
        manifest_path: manifest_path.clone(),
    });

    gc_sweep(&state_dir, &tree);

    assert!(snap_path.exists(), "pending snapshot must NOT be GC'd (zero-pid placeholder)");
    assert!(manifest_path.exists(), "pending manifest must NOT be GC'd");
    assert!(tree.get_run(pending_uuid).is_some(), "RunRecord preserved");
}

#[cfg_attr(not(target_os = "macos"), ignore)]
#[test]
fn gc_handles_missing_runs_dir_gracefully() {
    // If runs/ doesn't exist yet (daemon just started, no PrepareSnapshot
    // received), gc_sweep MUST NOT panic — it simply returns.
    let tmp = TempDir::new().unwrap();
    let state_dir = tmp.path().to_path_buf();
    let tree = Arc::new(ProcessTree::new());
    // Note: ensure_runs_dir NOT called — state_dir/runs/ doesn't exist.
    gc_sweep(&state_dir, &tree);
    // No panic = pass.
}
