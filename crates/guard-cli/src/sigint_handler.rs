//! crates/guard-cli/src/sigint_handler.rs
//!
//! v0.3 — SIGINT handler.
//!
//! On Ctrl-C during `stt-guard wrap`:
//!   1. Snapshot in-flight prompt_ids from the shared InflightPrompts registry.
//!   2. Send PromptCancel for each over the live prompt channel (so the daemon
//!      unblocks parked Resolve handlers with Deny).
//!   3. Propagate SIGINT to the wrapped command's process group via killpg.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use signal_hook::consts::SIGINT;
use signal_hook::iterator::{Handle, Signals};

use crate::CliError;
use crate::prompt_channel::{InflightPrompts, PromptChannel};

#[derive(Clone)]
pub struct SigIntHandle {
    stop: Arc<AtomicBool>,
    /// WR-01: signal-hook iterator handle. Calling `close()` unblocks
    /// `signals.forever()` so the spawned thread exits cleanly when this
    /// handle is dropped, instead of remaining parked until the next SIGINT
    /// arrives in this or any subsequent CLI invocation.
    handle: Handle,
}

pub type SharedChannel = Arc<Mutex<Option<PromptChannel>>>;

pub fn install(
    inflight: InflightPrompts,
    channel: SharedChannel,
    pgid: i32,
) -> Result<SigIntHandle, CliError> {
    let stop = Arc::new(AtomicBool::new(false));
    let stop_thread = Arc::clone(&stop);

    let mut signals = Signals::new([SIGINT])
        .map_err(|e| CliError::Other(format!("install SIGINT handler: {e}")))?;
    // WR-01: capture the handle BEFORE moving `signals` into the spawned
    // thread. Drop semantics call handle.close() to unblock forever().
    let handle = signals.handle();

    let _ = std::thread::Builder::new()
        .name("guard-sigint".into())
        .spawn(move || {
            if let Some(_sig) = signals.forever().next() {
                if stop_thread.load(Ordering::SeqCst) {
                    return;
                }
                handle_sigint(&inflight, &channel, pgid);
            }
        })
        .map_err(|e| CliError::Other(format!("spawn sigint thread: {e}")))?;

    Ok(SigIntHandle { stop, handle })
}

/// Synchronous core of the SIGINT handler. Extracted for unit testing.
pub fn handle_sigint(inflight: &InflightPrompts, channel: &SharedChannel, pgid: i32) {
    let prompts: Vec<String> = match inflight.0.lock() {
        Ok(g) => g.iter().cloned().collect(),
        Err(_) => Vec::new(),
    };
    if let Ok(mut g) = channel.lock() {
        if let Some(c) = g.as_mut() {
            for pid in &prompts {
                let _ = c.cancel(pid);
            }
        }
    }
    unsafe { libc::killpg(pgid, libc::SIGINT) };
}

impl Drop for SigIntHandle {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        // WR-01: unblock the parked `signals.forever()` iterator so the
        // sigint thread exits cleanly. Without this the thread sits there
        // until the next SIGINT in this process — which may never come, or
        // may arrive in a subsequent CLI invocation producing spurious
        // behavior.
        self.handle.close();
    }
}
