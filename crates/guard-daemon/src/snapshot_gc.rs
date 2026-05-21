//! Periodic GC for per-run snapshots.
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
///
/// WARNING part 2 (v0.2 review): for graceful shutdown, prefer
/// `spawn_gc_thread_with_shutdown` which takes a `crossbeam_channel::Receiver`
/// the daemon's signal handler can send on to ask the thread to exit. The
/// no-shutdown variant remains here for backwards compatibility — process
/// exit terminates the thread, which is acceptable but documented.
pub fn spawn_gc_thread(
    state_dir: std::path::PathBuf,
    tree: Arc<ProcessTree>,
) -> std::thread::JoinHandle<()> {
    std::thread::Builder::new()
        .name("stt-guard-daemon-gc".into())
        .spawn(move || {
            loop {
                gc_sweep(&state_dir, &tree);
                std::thread::sleep(Duration::from_secs(GC_INTERVAL_SECS));
            }
        })
        .expect("spawn gc thread")
}

/// Like `spawn_gc_thread` but exits cleanly when `shutdown` receives a value
/// (or is dropped — disconnected). Use this when the daemon needs to be able
/// to join on the GC thread during shutdown so a SIGTERM mid-sweep doesn't
/// leave a half-removed snapshot+manifest pair.
///
/// The channel select uses `select!` with the shutdown receiver and a
/// per-loop timeout equal to `GC_INTERVAL_SECS`. Shutdown latency is
/// therefore at most one sweep duration; `gc_sweep` itself is fast (a
/// stat'd directory walk), so practical shutdown is <100ms.
pub fn spawn_gc_thread_with_shutdown(
    state_dir: std::path::PathBuf,
    tree: Arc<ProcessTree>,
    shutdown: crossbeam_channel::Receiver<()>,
) -> std::thread::JoinHandle<()> {
    std::thread::Builder::new()
        .name("stt-guard-daemon-gc".into())
        .spawn(move || {
            loop {
                gc_sweep(&state_dir, &tree);
                crossbeam_channel::select! {
                    recv(shutdown) -> _ => return,
                    default(Duration::from_secs(GC_INTERVAL_SECS)) => continue,
                }
            }
        })
        .expect("spawn gc thread")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crossbeam_channel::bounded;

    #[test]
    fn shutdown_receiver_terminates_gc_thread() {
        // WARNING-07 part 2 regression: the with-shutdown variant must exit
        // promptly when the shutdown sender drops (or sends).
        let tmp = tempfile::tempdir().expect("tempdir");
        let tree = Arc::new(ProcessTree::new());
        let (tx, rx) = bounded::<()>(1);
        let handle = spawn_gc_thread_with_shutdown(tmp.path().to_path_buf(), tree, rx);
        // Drop the sender — the receiver becomes Disconnected, which
        // `select!`'s recv arm interprets as a closed channel returning Err.
        // Either branch (disconnect OR explicit send) terminates the loop.
        drop(tx);
        // The first sweep runs immediately; the next select should fire on
        // the disconnected channel within microseconds. Allow 5 seconds for
        // CI noise.
        let join_result = std::thread::Builder::new()
            .name("test-join-watcher".into())
            .spawn(move || handle.join())
            .expect("spawn watcher")
            .join();
        let watcher_result = join_result.expect("watcher thread join");
        assert!(watcher_result.is_ok(), "GC thread should join cleanly");
    }
}
