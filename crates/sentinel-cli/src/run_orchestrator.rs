//! crates/sentinel-cli/src/run_orchestrator.rs
//!
//! Phase 3 plan 03-13 (Phase 06 rename) — wrap-mode end-to-end orchestrator:
//! V3 PrepareSnapshot + prompt channel + spawn + wait + (optional) baseline-commit.
//! BLOCKER #1 SIGINT handler is registered here.

use std::ffi::OsString;
use std::io::{IsTerminal, Write as _};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use sha2::Digest;

use crate::CliError;

pub fn run(sock: &Path, state_dir: &Path, command: Vec<OsString>, learn_mode: bool) -> Result<i32, CliError> {
    let _ = state_dir; // currently unused; baseline IPC routes via sock
    let cwd = std::env::current_dir().map_err(|e| CliError::Other(format!("cwd: {e}")))?;
    let is_tty = std::io::stdin().is_terminal();

    crate::ipc_client::probe_daemon_alive(sock)?;

    // Phase 07 D-24/D-25: first-trust prompt for .sentinel.toml.
    // Walks up from cwd looking for .sentinel.toml (Phase 2 D-36 boundary).
    // If found and untrusted: TTY → prompt y/N + trust on yes; non-TTY →
    // auto-trust + stderr notice. The daemon re-hashes the file at the
    // TrustPolicy IPC handler (T-02-06a-01).
    if let Some(toml_path) = sentinel_core::policy_file::find_sentinel_toml(&cwd) {
        let canonical = toml_path.canonicalize()
            .map_err(|e| CliError::Other(format!("canonicalize {}: {e}", toml_path.display())))?;
        let canonical_str = canonical.display().to_string();
        let bytes = std::fs::read(&canonical)
            .map_err(|e| CliError::Other(format!("read {}: {e}", canonical.display())))?;
        let sha = format!("{:x}", sha2::Sha256::digest(&bytes));

        let trusted = crate::ipc_client::is_trusted_request(sock, &canonical_str, &sha)?;
        if !trusted {
            if is_tty {
                // Parse + display + prompt y/N.
                let toml_text = std::str::from_utf8(&bytes)
                    .map_err(|e| CliError::Other(format!("not UTF-8: {e}")))?;
                let parsed = sentinel_core::policy_file::parse(toml_text)
                    .map_err(|e| CliError::Other(format!("parse: {e}")))?;
                println!("Reviewing {}:", canonical.display());
                println!("  version = {}", parsed.version);
                crate::trust_policy::display_rules(&parsed);
                if crate::tty::confirm("Trust this file?")? {
                    crate::ipc_client::trust_policy_request(sock, &canonical_str, &sha)?;
                    println!("Trusted. (sha256={})", &sha[..12]);
                } else {
                    println!("Not trusted; rules will be ignored for this run.");
                }
            } else {
                // D-25: non-TTY auto-trust (file is committed + code-review-gated).
                crate::ipc_client::trust_policy_request(sock, &canonical_str, &sha)?;
                eprintln!(
                    "sentinel: trusted .sentinel.toml at {} (sha256={}; non-TTY auto-trust)",
                    canonical.display(),
                    &sha[..12],
                );
            }
        }
    }

    // Phase 4 plan 04-03: spawn a CR-overwrite progress thread on stderr while
    // the daemon does the synchronous feed fetch. The progress thread is
    // joined immediately after PrepareSnapshot returns; the line is cleared
    // with `\r\x1b[2K` so stderr returns to a clean state for any
    // feed_warnings or downstream output.
    let progress_stop = Arc::new(AtomicBool::new(false));
    let progress_handle = spawn_feed_progress_thread(Arc::clone(&progress_stop));

    let outcome = crate::ipc_client::prepare_snapshot_v3(sock, &cwd, is_tty, learn_mode);

    progress_stop.store(true, Ordering::SeqCst);
    let _ = progress_handle.join();

    let outcome = outcome?;
    let manifest_path = outcome.manifest_path.clone();
    let run_uuid = outcome.run_uuid.clone();

    // Phase 4 plan 04-03: surface non-fatal feed_warnings inline. Hard fetch
    // failures are already converted to CliError::Other by prepare_snapshot_v3
    // (D-85 strict-fail returns SnapshotReply::Err, which becomes the `?`
    // above). Warnings here are the D-87 partial-parse path.
    for w in &outcome.feed_warnings {
        eprintln!("\u{26A0} feed warning ({}): {} \u{2014} {}", w.feed, w.kind, w.message);
    }

    // Open PromptChannel BEFORE spawning the wrapped child. The shared mutex is
    // shared between the render-loop and the SIGINT handler.
    //
    // CR-02: take the reader out of the channel before stashing the channel in
    // the SharedChannel mutex. The render thread drives reads through the
    // exclusively-owned reader (no lock contention). The writer half stays in
    // the SharedChannel mutex so the SIGINT handler can call `cancel` on it
    // even while the render thread is parked in `next_prompt`.
    let shared_channel: crate::sigint_handler::SharedChannel = Arc::new(Mutex::new(None));
    let mut prompt_reader: Option<crate::prompt_channel::PromptReader> = None;
    let inflight_handle: Option<crate::prompt_channel::InflightPrompts> = if is_tty && !learn_mode {
        match crate::prompt_channel::PromptChannel::open(sock, &run_uuid) {
            Ok(mut channel) => {
                let inflight = channel.inflight_handle();
                prompt_reader = channel.take_reader();
                *shared_channel.lock().unwrap() = Some(channel);
                Some(inflight)
            }
            Err(e) => {
                tracing::warn!(error = %e, "PromptChannel::open failed; prompts unavailable for this run");
                None
            }
        }
    } else {
        None
    };

    // Spawn the wrapped child; capture pgid for SIGINT propagation.
    let (mut child, pgid) =
        crate::spawn::spawn_wrapped_with_pgid(&command, sock, &manifest_path, &run_uuid)?;

    // quick-260508-et9 (Rule 3 fix to a blocking pre-existing regression):
    // Restore the RegisterRoot delegation that was lost in the Phase 03-13
    // refactor (commit d020752 — extracted run_orchestrator from main.rs and
    // dropped the audit_token + register_root_with_daemon call sites).
    //
    // Without this, the daemon's `is_tracked(peer_token)` returns false for
    // every IPC the wrapped child sends (DylibLoaded, ForkEvent, ExecEvent,
    // EnvNotPropagatedGap). The TREE-06 e2e tests, the BLOCKER #1 pm_env
    // capture e2e tests, and any other test that depends on
    // tree-tracked-peer state ALL silently fail when this call is missing —
    // the dylib's IPC succeeds at the wire layer but is rejected at the
    // handler-level untracked-peer gate.
    //
    // We obtain the wrapped child's audit token via task_info(TASK_AUDIT_TOKEN)
    // (kernel-sourced; same-uid only). REGISTER-01 delegation: peer_token
    // is the CLI's own kernel-sourced token, wire-claimed token is the
    // child's — daemon trusts the wire token after verify_wire_pid_same_uid
    // (WR-08). See ipc_server.rs handle_legacy_register comment block.
    let child_pid = child.id() as libc::pid_t;
    let token = crate::audit_token::audit_token_for_pid(child_pid)
        .map_err(|e| CliError::DaemonUnreachable(format!("audit_token: {e}")))?;
    crate::ipc_client::register_root_with_daemon(sock, token)?;

    // BLOCKER #1 / CR-01: ALWAYS install the SIGINT handler so Ctrl-C reliably
    // propagates to the wrapped child's process group, even when the prompt
    // channel is unavailable (non-TTY, baseline mode, R-05 cap, schema skew,
    // transient daemon error). When `inflight_handle` is None we install with
    // an empty in-flight registry; `handle_sigint` tolerates an absent channel
    // and a zero-length set, falling through to the load-bearing `killpg`.
    let inflight_for_sigint = inflight_handle
        .clone()
        .unwrap_or_default();
    let _sigint_handle = crate::sigint_handler::install(
        inflight_for_sigint,
        Arc::clone(&shared_channel),
        pgid,
    )?;

    // Render-loop thread (only when interactive AND not baseline-recording).
    //
    // CR-02: the thread owns the `PromptReader` directly and reads without
    // holding the SharedChannel mutex. Writes (`answer`/`cancel`) go through
    // the SharedChannel mutex which is also held briefly by the SIGINT
    // handler — but never simultaneously with a blocking read.
    let stop_flag = Arc::new(AtomicBool::new(false));
    let render_handle = if let Some(reader) = prompt_reader.take() {
        let shared = Arc::clone(&shared_channel);
        let stop = Arc::clone(&stop_flag);
        Some(
            std::thread::Builder::new()
                .name("sentinel-prompt-render".into())
                .spawn(move || render_loop(reader, shared, stop))
                .map_err(|e| CliError::Other(format!("render thread: {e}")))?,
        )
    } else {
        None
    };

    // Wait for child.
    let exit_status = child.wait().map_err(|e| CliError::Other(format!("wait: {e}")))?;
    let exit_code = exit_status.code().unwrap_or(1);

    // Baseline commit flow.
    if learn_mode {
        if let Err(e) = crate::baseline::run_baseline_commit(sock, &run_uuid) {
            eprintln!("baseline commit error: {e}");
        }
    }

    // WR-13: drop the SharedChannel writer half so the render thread's blocked
    // `read_frame` returns Err (the daemon-side reader exits when our writer
    // closes the socket; on its half-close the kernel propagates EOF back to
    // our reader). Without this, `render_handle.join()` would sit forever
    // because the daemon won't proactively close the channel after the run
    // ends — it relies on the CLI side to drop the socket on exit.
    if let Ok(mut g) = shared_channel.lock() {
        *g = None;
    }
    stop_flag.store(true, Ordering::SeqCst);
    if let Some(h) = render_handle {
        let _ = h.join();
    }
    Ok(exit_code)
}

/// Phase 4 plan 04-03 — CR-overwrite stderr progress while the daemon is in
/// the middle of `fetch_feeds_blocking`. The thread frame-cycles on a 250ms
/// tick. On stop, prints `\r\x1b[2K` to clear the line so subsequent stderr
/// output (feed_warnings, child output) starts from column 0.
///
/// Per CONTEXT.md: the `\u{26A1}` (lightning bolt) is intentional — it's the
/// design's emotional payoff. CLAUDE.md's no-emoji rule applies to assistant
/// chat output, not user-facing UX strings the design explicitly specifies.
fn spawn_feed_progress_thread(stop: Arc<AtomicBool>) -> std::thread::JoinHandle<()> {
    std::thread::Builder::new()
        .name("sentinel-feed-progress".into())
        .spawn(move || {
            let frames = ["osv... ghsa...", "osv ... ghsa..", "osv .. ghsa.."];
            let mut i = 0usize;
            while !stop.load(Ordering::Relaxed) {
                let _ = write!(
                    std::io::stderr(),
                    "\r\u{26A1} Refreshing threat feeds ({})  ",
                    frames[i % frames.len()]
                );
                let _ = std::io::stderr().flush();
                std::thread::sleep(Duration::from_millis(250));
                i += 1;
            }
            // Clear the progress line so downstream stderr output starts clean.
            let _ = write!(std::io::stderr(), "\r\x1b[2K");
            let _ = std::io::stderr().flush();
        })
        .expect("spawn feed progress thread")
}

fn render_loop(
    mut reader: crate::prompt_channel::PromptReader,
    shared_channel: crate::sigint_handler::SharedChannel,
    stop: Arc<AtomicBool>,
) {
    while !stop.load(Ordering::SeqCst) {
        // CR-02: blocking read happens on the exclusively-owned reader half;
        // we DO NOT hold the SharedChannel lock while parked here. The SIGINT
        // handler can therefore acquire the SharedChannel lock to call cancel
        // on the writer half while we're still parked.
        let req = match reader.next_prompt() {
            Ok(r) => r,
            Err(_) => break, // EOF / disconnect / channel teardown
        };
        match crate::prompt_render::render_and_choose(&req) {
            Ok(resp) => {
                if let Ok(mut g) = shared_channel.lock() {
                    if let Some(c) = g.as_mut() {
                        let _ = c.answer(resp);
                    }
                }
            }
            Err(e) => {
                tracing::warn!(error = %e, "prompt render failed; cancelling");
                if let Ok(mut g) = shared_channel.lock() {
                    if let Some(c) = g.as_mut() {
                        let _ = c.cancel(&req.prompt_id);
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn feed_progress_thread_starts_and_stops_cleanly() {
        // Smoke test: spawning the thread, signalling stop, joining all
        // happen without panic. We can't easily redirect this thread's
        // stderr output (it writes via std::io::stderr() directly) so the
        // assertion is process-survival + clean join.
        let stop = Arc::new(AtomicBool::new(false));
        let h = spawn_feed_progress_thread(Arc::clone(&stop));
        // Let one tick fire so the worker actually executes the loop body.
        std::thread::sleep(Duration::from_millis(50));
        stop.store(true, Ordering::Relaxed);
        h.join().expect("progress thread joins cleanly");
    }
}
