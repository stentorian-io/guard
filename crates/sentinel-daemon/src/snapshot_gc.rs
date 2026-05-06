//! Periodic GC for per-run snapshots (D-29).
//!
//! Sweeps `runs/*.cbor` every GC_INTERVAL_SECS:
//!   - If the file has no matching RunRecord in the ProcessTree, remove it
//!     (orphaned — daemon restarted between PrepareSnapshot and GC).
//!   - If the RunRecord's tracked_root pid is no longer alive (probe via
//!     `kill(pid, 0)`), gc_run + tree.remove_run.
//!   - If the RunRecord's tracked_root.val[5] (pid slot) is zero, the record
//!     is in the post-PrepareSnapshot / pre-RegisterRoot window — leave it
//!     alone for the next sweep.
//!
//! Conservative on errors: any I/O failure during sweep is logged at warn or
//! debug level and the file is left for the next sweep.
//!
//! T-02-07-01 (PID-reuse race): `kill(pid, 0)` only validates that *some*
//! process holds that pid; it does NOT validate pidversion. PID reuse within
//! a 30s window is extremely rare on macOS (pid_max is ~99999, sequential
//! allocation). Worst case: GC removes a snapshot whose pid is reused; the
//! wrapped process then sees its mmap go away and FAIL_CLOSED — which is the
//! safe outcome (deny rather than silently allow).

use crate::snapshot::gc_run;
use crate::state_dir::runs_dir;
use crate::tracked::ProcessTree;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use tracing::{debug, info};

pub const GC_INTERVAL_SECS: u64 = 30;

/// One-shot sweep over `runs/*.cbor`. Removes orphaned files and snapshots
/// whose tracked_root pid is no longer alive. Idempotent and side-effect-only;
/// safe to call concurrently with PrepareSnapshot (the worst case is two GC
/// passes overlapping, which both see the same on-disk state).
pub fn gc_sweep(state_dir: &Path, tree: &ProcessTree) {
    let dir = runs_dir(state_dir);
    let entries = match std::fs::read_dir(&dir) {
        Ok(e) => e,
        Err(e) => {
            // No runs/ subdir yet (daemon just started, no PrepareSnapshot yet).
            debug!(error = %e, dir = %dir.display(), "gc_sweep: read_dir failed (likely runs/ not yet created)");
            return;
        }
    };
    let mut removed = 0u32;
    for ent in entries.flatten() {
        let path = ent.path();
        // Walk only by .cbor; gc_run() handles the matching .manifest sibling.
        if path.extension().and_then(|e| e.to_str()) != Some("cbor") {
            continue;
        }
        let stem = match path.file_stem().and_then(|s| s.to_str()) {
            Some(s) => s,
            None => continue,
        };
        // Skip dotfiles (in-flight tmp like `.{uuid}.cbor.tmp` — although
        // those have extension .tmp, not .cbor, so this is belt-and-braces).
        if stem.starts_with('.') {
            continue;
        }
        let run_uuid = stem.to_string();
        let record = tree.get_run(&run_uuid);
        let should_gc = match record {
            None => {
                // Orphan: file exists but no RunRecord. Daemon restart left it behind.
                debug!(run_uuid = %run_uuid, "gc_sweep: orphaned run snapshot");
                true
            }
            Some(rec) => {
                // tracked_root.val[5] is the pid slot in the kernel-emitted
                // audit_token layout (Darwin sys/audit.h: token.val[5] == pid).
                let pid = rec.tracked_root.val[5] as libc::pid_t;
                if pid == 0 {
                    // RunRecord exists but tracked_root not yet bound (PrepareSnapshot
                    // happened but RegisterRoot hasn't yet). Skip — too early to GC.
                    false
                } else {
                    // BLOCKER-06 fix: only `errno == ESRCH` definitively means
                    // the process is dead. The previous code treated any
                    // errno other than EPERM as "dead", which mis-classified
                    // EINVAL / EFAULT / future macOS errno expansions and
                    // could GC a snapshot whose tracked_root is still
                    // running. A wrongly-GC'd snapshot leaves the dylib
                    // running against a phantom mmap (or, after re-publish,
                    // the wrong CBOR contents) — exactly the failure mode
                    // the comment claimed the code was preventing.
                    //
                    // kill(pid, 0) results:
                    //   0          → alive (signal could be delivered)
                    //   -1 ESRCH   → dead (no such process)
                    //   -1 EPERM   → alive but not signal-able (alive)
                    //   -1 OTHER   → uncertain → conservative: alive
                    let r = unsafe { libc::kill(pid, 0) };
                    let alive = if r == 0 {
                        true
                    } else {
                        let err = unsafe { *libc::__error() };
                        err != libc::ESRCH
                    };
                    !alive
                }
            }
        };
        if should_gc {
            gc_run(state_dir, &run_uuid);
            tree.remove_run(&run_uuid);
            removed += 1;
        }
    }
    if removed > 0 {
        info!(count = removed, "gc_sweep: removed stale per-run snapshots");
    }
}

/// Spawn a background thread that calls `gc_sweep` every GC_INTERVAL_SECS.
/// The handle is intentionally returned for tests that may want to join;
/// the daemon's serve() detaches it (thread runs as long as the process).
pub fn spawn_gc_thread(
    state_dir: std::path::PathBuf,
    tree: Arc<ProcessTree>,
) -> std::thread::JoinHandle<()> {
    std::thread::Builder::new()
        .name("sentineld-gc".into())
        .spawn(move || loop {
            gc_sweep(&state_dir, &tree);
            std::thread::sleep(Duration::from_secs(GC_INTERVAL_SECS));
        })
        .expect("spawn gc thread")
}
