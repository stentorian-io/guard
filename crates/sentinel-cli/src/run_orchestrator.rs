//! crates/sentinel-cli/src/run_orchestrator.rs
//!
//! Phase 3 plan 03-13 — `sentinel run` end-to-end orchestrator:
//! V3 PrepareSnapshot + prompt channel + spawn + wait + (optional) baseline-commit.
//! BLOCKER #1 SIGINT handler is registered here.

use std::ffi::OsString;
use std::io::IsTerminal;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use crate::CliError;

pub fn run(sock: &Path, state_dir: &Path, command: Vec<OsString>, baseline_mode: bool) -> Result<i32, CliError> {
    let _ = state_dir; // currently unused; baseline IPC routes via sock
    let cwd = std::env::current_dir().map_err(|e| CliError::Other(format!("cwd: {e}")))?;
    let is_tty = std::io::stdin().is_terminal();

    crate::ipc_client::probe_daemon_alive(sock)?;
    let (manifest_path, run_uuid) =
        crate::ipc_client::prepare_snapshot_v3(sock, &cwd, is_tty, baseline_mode)?;

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
    let inflight_handle: Option<crate::prompt_channel::InflightPrompts> = if is_tty && !baseline_mode {
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
    if baseline_mode {
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
