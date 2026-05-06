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
    let shared_channel: crate::sigint_handler::SharedChannel = Arc::new(Mutex::new(None));
    let inflight_handle: Option<crate::prompt_channel::InflightPrompts> = if is_tty && !baseline_mode {
        match crate::prompt_channel::PromptChannel::open(sock, &run_uuid) {
            Ok(channel) => {
                let inflight = channel.inflight_handle();
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

    // BLOCKER #1: register SIGINT handler now that pgid is known and channel is open.
    let _sigint_handle = if let Some(ref inflight) = inflight_handle {
        Some(crate::sigint_handler::install(
            inflight.clone(),
            Arc::clone(&shared_channel),
            pgid,
        )?)
    } else {
        None
    };

    // Render-loop thread (only when interactive AND not baseline-recording).
    let stop_flag = Arc::new(AtomicBool::new(false));
    let render_handle = if inflight_handle.is_some() {
        let shared = Arc::clone(&shared_channel);
        let stop = Arc::clone(&stop_flag);
        Some(
            std::thread::Builder::new()
                .name("sentinel-prompt-render".into())
                .spawn(move || render_loop(shared, stop))
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

    // Stop render loop.
    stop_flag.store(true, Ordering::SeqCst);
    if let Some(h) = render_handle {
        let _ = h.join();
    }
    Ok(exit_code)
}

fn render_loop(
    shared_channel: crate::sigint_handler::SharedChannel,
    stop: Arc<AtomicBool>,
) {
    while !stop.load(Ordering::SeqCst) {
        let req_result = {
            let mut g = match shared_channel.lock() {
                Ok(g) => g,
                Err(_) => return,
            };
            match g.as_mut() {
                Some(c) => Some(c.next_prompt()),
                None => None,
            }
        };
        match req_result {
            Some(Ok(req)) => {
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
            Some(Err(_)) | None => break,
        }
    }
}
