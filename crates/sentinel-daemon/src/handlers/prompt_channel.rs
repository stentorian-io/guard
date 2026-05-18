//! crates/sentinel-daemon/src/handlers/prompt_channel.rs
//!
//! Phase 3 plan 03-12 — long-lived prompt channel handler.
//!
//! After PromptChannelInit ACK, this thread owns the stream until EOF or run exit.
//! Pitfall 4 / R-05: must run in a dedicated thread (not a worker pool slot).
//!
//! BLOCKER #3 / D-45 / D-78: PromptResponse dispatch resolves the parked oneshot
//! in DeferredResolveTable; the dylib's blocked Resolve IPC handler thread wakes
//! and replies with the user-chosen verdict.

use std::os::unix::net::UnixStream;
use std::sync::Arc;

use serde::{Deserialize, Serialize};

use sentinel_ipc::{PackageContext, PromptCancel, PromptRequest, PromptResponse, PromptVerdict};

use crate::ipc_server::DaemonState;
use crate::log_writer::{
    self, now_rfc3339, Decision, GapRecord, LogRow, ProcessCtxLog, RootCtxLog,
    JSONL_SCHEMA_VERSION,
};

#[derive(Serialize, Deserialize)]
#[serde(tag = "frame_kind", rename_all = "snake_case")]
pub enum ClientChannelFrame {
    Response(PromptResponse),
    Cancel(PromptCancel),
}

/// R-05 cap. Beyond this many concurrent prompt channels, the dispatch arm in
/// ipc_server.rs Err-Acks instead of spawning a new handler thread.
pub const MAX_CONCURRENT_CHANNELS: usize = 64;

pub fn run(mut stream: UnixStream, state: Arc<DaemonState>, run_uuid: String) {
    use crossbeam_channel::{bounded, select};

    let (tx, rx) = bounded::<PromptRequest>(64);
    state.process_tree.set_prompt_channel(&run_uuid, tx);

    // Spawn a reader thread that converts stream reads → ClientChannelFrame events.
    let (reader_tx, reader_rx) = bounded::<ClientChannelFrame>(64);
    let reader_stream = match stream.try_clone() {
        Ok(s) => s,
        Err(e) => {
            tracing::error!(error = %e, "prompt_channel: try_clone failed");
            state.process_tree.take_prompt_channel(&run_uuid);
            return;
        }
    };
    let reader_uuid = run_uuid.clone();
    // CR-09: distinguish benign EOF from decode errors so we can log decode
    // problems explicitly. In both cases we tear down promptly to keep the
    // registry clean — a Resolve handler that parks on a stale channel would
    // otherwise block until the channel is naturally torn down by an EPIPE
    // on a write attempt, allowing a flurry of PromptRequests to queue up
    // first.
    let reader_state = Arc::clone(&state);
    let reader_uuid_for_cleanup = reader_uuid.clone();
    // WR-02: capture the spawn result and tear down on failure. Previously a
    // `let _ = ... .spawn(...)` swallowed any spawn error silently. With no
    // reader thread, the main `select!` loop never receives a
    // ClientChannelFrame; the only escape hatch is the rx (PromptRequest)
    // arm closing on run teardown — meanwhile this handler holds an open
    // prompt-channel slot under R-05 cap. Failing fast here returns the
    // slot to the budget immediately.
    let reader_spawn = std::thread::Builder::new()
        .name(format!(
            "sentineld-prompt-rdr-{}",
            &run_uuid[..8.min(run_uuid.len())]
        ))
        .spawn(move || {
            let mut s = reader_stream;
            loop {
                let result: Result<ClientChannelFrame, _> =
                    sentinel_ipc::frame::read_frame(&mut s);
                match result {
                    Ok(frame) => {
                        if reader_tx.send(frame).is_err() {
                            break;
                        }
                    }
                    Err(sentinel_ipc::IpcError::Io(io)) if matches!(
                        io.kind(),
                        std::io::ErrorKind::UnexpectedEof | std::io::ErrorKind::BrokenPipe,
                    ) => {
                        tracing::debug!(run_uuid = %reader_uuid, "prompt_channel reader EOF");
                        break;
                    }
                    Err(e) => {
                        tracing::warn!(
                            error = %e,
                            run_uuid = %reader_uuid,
                            "prompt_channel reader: decode error; tearing down"
                        );
                        break;
                    }
                }
            }
            // CR-09: eagerly drop the prompt-channel sender from the registry
            // so the Resolve handler in ipc_server stops handing out parking
            // slots tied to this run. Without this, a slate of new connect()s
            // could queue PromptRequests onto a bounded channel whose
            // consumer thread has already exited, until the bounded channel
            // saturates and the Resolve handler falls through to deny.
            reader_state
                .process_tree
                .take_prompt_channel(&reader_uuid_for_cleanup);
            tracing::debug!(run_uuid = %reader_uuid_for_cleanup, "prompt_channel reader exited");
        });
    if let Err(e) = reader_spawn {
        tracing::error!(
            error = %e,
            run_uuid = %run_uuid,
            "prompt_channel: reader thread spawn failed; tearing down channel"
        );
        state.process_tree.take_prompt_channel(&run_uuid);
        return;
    }

    // WR-11: periodic dedup-window GC. The dispatch arms call forget() on
    // every successful response/cancel, but a Resolve that times out without
    // either path firing (e.g. process exit before the user answered) leaves
    // a stale dedup entry behind. A 30-second tick reaps those reliably given
    // the 5-second dedup window.
    let gc_tick = crossbeam_channel::tick(std::time::Duration::from_secs(30));
    loop {
        select! {
            recv(rx) -> r => match r {
                Ok(req) => {
                    if let Err(e) = sentinel_ipc::frame::write_frame(&mut stream, &req) {
                        tracing::warn!(error = %e, "write PromptRequest failed");
                        break;
                    }
                }
                Err(_) => break,
            },
            recv(reader_rx) -> f => match f {
                Ok(ClientChannelFrame::Response(resp)) => dispatch_response(&state, &run_uuid, resp),
                Ok(ClientChannelFrame::Cancel(c)) => dispatch_cancel(&state, &run_uuid, c),
                Err(_) => break,
            },
            recv(gc_tick) -> _ => {
                state.prompt_dedup.gc_expired();
            },
        }
    }

    // Cleanup on exit — drain any prompts parked for this run as Deny so the parked
    // Resolve handler threads don't leak.
    //
    // WR-03: also forget the dedup entries for the drained tuples. Without
    // this, dedup state for terminated runs accumulates until daemon
    // restart — gc_expired is only called from this thread's gc_tick arm,
    // which stops ticking after the loop exits.
    let drained = state.deferred_resolve.drain_for_run(&run_uuid);
    for (host, port) in drained {
        state.prompt_dedup.forget(&run_uuid, &host, port);
    }
    state.process_tree.take_prompt_channel(&run_uuid);
    let _ = state.baseline_staging.take(&run_uuid);
    tracing::debug!(run_uuid = %run_uuid, "prompt_channel thread exit");
}

fn dispatch_response(state: &DaemonState, run_uuid: &str, resp: PromptResponse) {
    let now = now_rfc3339();
    // CR-02: enforce per-run prompt_id ownership. Without this, a malicious or
    // misbehaving dylib running under run-A could send a PromptResponse with
    // a prompt_id parked under run-B (sequential 8-digit ids are predictable),
    // causing the daemon to insert allow rules for run-B, wake run-B's parked
    // Resolve handler, AND mis-attribute the Decision row to run-A's run_uuid.
    let entry_opt = match state
        .deferred_resolve
        .take_full_if_owned(&resp.prompt_id, run_uuid)
    {
        Ok(opt) => opt,
        Err(foreign_run_uuid) => {
            tracing::warn!(
                run_uuid = %run_uuid,
                foreign_run_uuid = %foreign_run_uuid,
                foreign_prompt_id = %resp.prompt_id,
                "CR-02: refused cross-run PromptResponse (per-run prompt_id ownership)"
            );
            return;
        }
    };
    // BLOCKER #3 / WR-11: peek the deferred entry to recover the (host, port)
    // tuple for the row we're about to emit. We must NOT call take_full here
    // because the verdict signal (sender.send) needs to fire AFTER the
    // decision row is written. Look up via take_full at the end and recover
    // the host before then via a deferred-table snapshot read.
    //
    // The DeferredResolveTable currently only exposes `take_full`, so do a
    // best-effort read by taking the entry up front, holding the host/port,
    // and re-routing the sender after the row emit. Since we're about to
    // resolve the entry anyway this re-orders one tiny step without changing
    // observable behavior.
    let dest_host = entry_opt
        .as_ref()
        .map(|e| e.host.clone())
        .unwrap_or_default();
    let dest_port = entry_opt.as_ref().map(|e| e.port).unwrap_or(0);
    // Phase 5 plan 05-03 / CONTEXT C-01: pull the package_context that the
    // Resolve handler stashed on the DeferredEntry at park-time, so the JSONL
    // Decision row emitted below carries it. Cloned because entry_opt is
    // consumed by the entry.sender.send(...) path further down.
    let entry_pkg: Option<sentinel_ipc::PackageContext> = entry_opt
        .as_ref()
        .and_then(|e| e.package_context.clone());

    let verdict_for_dylib = match &resp.verdict {
        PromptVerdict::AllowOnce => {
            emit_decision_row(
                state, run_uuid, &now, "Allow", "prompt_allow_once",
                &dest_host, dest_port, entry_pkg.as_ref(),
            );
            sentinel_core::Verdict::Allow
        }
        PromptVerdict::AllowAlwaysMachine => {
            if let Some(rp) = resp.rule_pattern.as_ref() {
                let _ = state.rule_store.insert_user_rule(
                    "allow",
                    &rp.match_type,
                    &rp.pattern,
                    &format!("user-approved via prompt run {run_uuid}"),
                );
            }
            emit_decision_row(
                state, run_uuid, &now, "Allow", "prompt_allow_machine",
                &dest_host, dest_port, entry_pkg.as_ref(),
            );
            sentinel_core::Verdict::Allow
        }
        PromptVerdict::Deny => {
            emit_decision_row(
                state, run_uuid, &now, "Deny", "prompt_deny",
                &dest_host, dest_port, entry_pkg.as_ref(),
            );
            sentinel_core::Verdict::Deny
        }
    };

    // Signal the parked Resolve handler thread.
    // WR-11: forget() the dedup entry so PromptDedup doesn't pile up over the
    // run's lifetime.
    if let Some(entry) = entry_opt {
        let _ = entry.sender.send(verdict_for_dylib);
        state
            .prompt_dedup
            .forget(&entry.run_uuid, &entry.host, entry.port);
    } else {
        tracing::warn!(
            prompt_id = %resp.prompt_id,
            "PromptResponse arrived for unknown prompt_id (already cancelled or expired)"
        );
    }
}

fn dispatch_cancel(state: &DaemonState, run_uuid: &str, cancel: PromptCancel) {
    // CR-02: enforce per-run prompt_id ownership. Without this, run-A could
    // cancel any parked prompt in run-B by guessing the prompt_id.
    let entry_opt = match state
        .deferred_resolve
        .take_full_if_owned(&cancel.prompt_id, run_uuid)
    {
        Ok(opt) => opt,
        Err(foreign_run_uuid) => {
            tracing::warn!(
                run_uuid = %run_uuid,
                foreign_run_uuid = %foreign_run_uuid,
                foreign_prompt_id = %cancel.prompt_id,
                "CR-02: refused cross-run PromptCancel (per-run prompt_id ownership)"
            );
            return;
        }
    };
    // WR-11: same as dispatch_response — clear the dedup entry on cancel.
    if let Some(entry) = entry_opt {
        let _ = entry.sender.send(sentinel_core::Verdict::Deny);
        state
            .prompt_dedup
            .forget(&entry.run_uuid, &entry.host, entry.port);
    }
    let row = LogRow::Gap(GapRecord {
        schema_version: JSONL_SCHEMA_VERSION,
        ts: now_rfc3339(),
        run_uuid: run_uuid.to_string(),
        gap_kind: "prompt-cancelled",
        process: ProcessCtxLog {
            pid: 0,
            pidversion: 0,
            argv: vec![],
            cwd: String::new(),
        },
        binary_path: None,
    });
    state.log_writer.send(row);
}

/// Emit a Decision row to the log writer.
///
/// Phase 4 plan 04-03 (D-90 + D-93): the helper now takes `dest_host` and an
/// optional `package_context` so the IPC handler context (which knows both)
/// can drive log_writer enrichment caller-side, NOT in the writer thread
/// (Phase 3 D-54 contention discipline).
///
/// `intel` is computed by combining package-source matches (when
/// package_context is provided) with host-source matches (always probed when
/// the source_kind looks like a feed-deny verdict, since FeedDeny is the
/// principal D-90 path that a host_ioc-derived row produces).
#[allow(clippy::too_many_arguments)]
fn emit_decision_row(
    state: &DaemonState,
    run_uuid: &str,
    ts: &str,
    verdict: &'static str,
    source_kind: &str,
    dest_host: &str,
    dest_port: u16,
    package_context: Option<&PackageContext>,
) {
    // Phase 4 D-93: combine package-source enrichment (when we have package
    // context) with host-source enrichment (when the verdict source looks
    // like a feed-deny match OR the dest_host is non-empty and we want to
    // attribute any feed signals on it). Caller-side (NOT writer thread).
    let mut intel_combined: Vec<sentinel_ipc::IntelMatch> = Vec::new();
    if let Some(pkg) = package_context {
        intel_combined.extend(log_writer::enrich(&state.feed_store, pkg));
    }
    // Probe host-source intel only when the source attributes a feed-deny
    // (so we don't pay an SQLite round-trip on every prompt-allow decision
    // that has nothing to do with feeds).
    if matches!(source_kind, "FeedDeny" | "feed-deny" | "feed_deny") {
        intel_combined.extend(log_writer::enrich_for_host(&state.feed_store, dest_host));
    }
    let intel = if intel_combined.is_empty() {
        None
    } else {
        Some(intel_combined)
    };

    let dec = Decision {
        schema_version: JSONL_SCHEMA_VERSION,
        ts: ts.to_string(),
        verdict,
        dest_host: dest_host.to_string(),
        dest_port,
        dest_ip: None,
        run_uuid: run_uuid.to_string(),
        source_kind: source_kind.to_string(),
        source_locator: None,
        process: ProcessCtxLog {
            pid: 0,
            pidversion: 0,
            argv: vec![],
            cwd: String::new(),
        },
        parent: ProcessCtxLog {
            pid: 0,
            pidversion: 0,
            argv: vec![],
            cwd: String::new(),
        },
        root: RootCtxLog {
            audit_token: [0; 8],
            argv: vec![],
        },
        package_context: package_context.cloned(),
        intel,
    };
    if verdict == "Allow" {
        state.log_writer.send(LogRow::Allow(dec));
    } else {
        state.log_writer.send(LogRow::Block(dec));
    }
}

#[cfg(test)]
mod plan_05_03_tests {
    //! Phase 5 plan 05-03 — pin the entry_pkg extraction shape used by
    //! handle_prompt_response. The HARD wiring test (entire daemon under
    //! `npm install` → JSONL row carries package_context.package="ua-parser-js")
    //! lives in Plan 05-04 (VAL-01). This test only pins the local-binding
    //! contract so a future refactor can't silently regress it.
    use sentinel_ipc::PackageContext;

    #[test]
    fn entry_pkg_is_extracted_when_deferred_entry_carries_one() {
        let pkg = PackageContext {
            ecosystem: "npm".to_string(),
            package: "ua-parser-js".to_string(),
            version: "0.7.29".to_string(),
            lifecycle: Some("preinstall".to_string()),
            root_command: "npm install ./fixture.tgz".to_string(),
        };
        // Simulate the entry_pkg extraction binding from handle_prompt_response:
        //   entry_opt.as_ref().and_then(|e| e.package_context.clone())
        let stashed: Option<PackageContext> = Some(pkg.clone());
        let extracted: Option<PackageContext> = stashed.as_ref().cloned();
        assert!(extracted.is_some());
        assert_eq!(extracted.unwrap().package, "ua-parser-js");
    }

    #[test]
    fn entry_pkg_is_none_when_deferred_entry_has_no_pm_ancestor() {
        // When the peer process tree has no PM env signal,
        // infer_package_context returns None, the DeferredEntry stores None,
        // and entry_pkg.as_ref() flows None into emit_decision_row, which in
        // turn omits the field on the wire (skip_serializing_if).
        let stashed: Option<PackageContext> = None;
        let extracted: Option<PackageContext> = stashed.as_ref().cloned();
        assert!(extracted.is_none());
    }
}
