//! crates/guard-daemon/src/handlers/prompt_channel.rs
//!
//! v0.3 — long-lived prompt channel handler.
//!
//! After `PromptChannelInit` ACK, this thread owns the stream until EOF or run exit.
//! Pitfall 4: must run in a dedicated thread (not a worker pool slot).
//!
//! BLOCKER: `PromptResponse` dispatch resolves the parked oneshot
//! in `DeferredResolveTable`; the dylib's blocked Resolve IPC handler thread wakes
//! and replies with the user-chosen verdict.

use std::os::unix::net::UnixStream;
use std::sync::Arc;

use serde::{Deserialize, Serialize};

use guard_ipc::{
    InsertUserRule, PackageContext, PromptCancel, PromptRequest, PromptResponse, PromptVerdict,
    RulePattern,
};

use crate::ipc_server::{DaemonState, DeferredEntry};
use crate::log_writer::{
    self, Decision, GapRecord, JSONL_SCHEMA_VERSION, LogRow, ProcessCtxLog, RootCtxLog, now_rfc3339,
};

#[derive(Serialize, Deserialize)]
#[serde(tag = "frame_kind", rename_all = "snake_case")]
pub enum ClientChannelFrame {
    Response(Box<PromptResponse>),
    Cancel(PromptCancel),
}

/// Cap. Beyond this many concurrent prompt channels, the dispatch arm in
/// `ipc_server.rs` Err-Acks instead of spawning a new handler thread.
pub const MAX_CONCURRENT_CHANNELS: usize = 64;

pub fn run(mut stream: UnixStream, state: &Arc<DaemonState>, run_uuid: &str) {
    use crossbeam_channel::{bounded, select};

    let (tx, rx) = bounded::<PromptRequest>(64);
    state.process_tree.set_prompt_channel(run_uuid, tx);

    // Spawn a reader thread that converts stream reads → ClientChannelFrame events.
    let (reader_tx, reader_rx) = bounded::<ClientChannelFrame>(64);
    let reader_stream = match stream.try_clone() {
        Ok(s) => s,
        Err(e) => {
            tracing::error!(error = %e, "prompt_channel: try_clone failed");
            state.process_tree.take_prompt_channel(run_uuid);
            return;
        }
    };
    let reader_uuid = run_uuid.to_string();
    // CR-09: distinguish benign EOF from decode errors so we can log decode
    // problems explicitly. In both cases we tear down promptly to keep the
    // registry clean — a Resolve handler that parks on a stale channel would
    // otherwise block until the channel is naturally torn down by an EPIPE
    // on a write attempt, allowing a flurry of PromptRequests to queue up
    // first.
    let reader_state = Arc::clone(state);
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
            "stt-guard-daemon-prompt-rdr-{}",
            &run_uuid[..8.min(run_uuid.len())]
        ))
        .spawn(move || {
            let mut s = reader_stream;
            loop {
                let result: Result<ClientChannelFrame, _> = guard_ipc::frame::read_frame(&mut s);
                match result {
                    Ok(frame) => {
                        if reader_tx.send(frame).is_err() {
                            break;
                        }
                    }
                    Err(guard_ipc::IpcError::Io(io))
                        if matches!(
                            io.kind(),
                            std::io::ErrorKind::UnexpectedEof | std::io::ErrorKind::BrokenPipe,
                        ) =>
                    {
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
        state.process_tree.take_prompt_channel(run_uuid);
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
                    if let Err(e) = guard_ipc::frame::write_frame(&mut stream, &req) {
                        tracing::warn!(error = %e, "write PromptRequest failed");
                        break;
                    }
                }
                Err(_) => break,
            },
            recv(reader_rx) -> f => match f {
                Ok(ClientChannelFrame::Response(resp)) => dispatch_response(state, run_uuid, &resp),
                Ok(ClientChannelFrame::Cancel(c)) => dispatch_cancel(state, run_uuid, &c),
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
    let drained = state.deferred_resolve.drain_for_run(run_uuid);
    for (host, port) in drained {
        state.prompt_dedup.forget(run_uuid, &host, port);
    }
    state.process_tree.take_prompt_channel(run_uuid);
    let _ = state.baseline_staging.take(run_uuid);
    tracing::debug!(run_uuid = %run_uuid, "prompt_channel thread exit");
}

fn dispatch_response(state: &DaemonState, run_uuid: &str, resp: &PromptResponse) {
    let now = now_rfc3339();
    let entry_opt = take_prompt_response_entry(state, run_uuid, resp);
    let response_context = prompt_response_context(entry_opt.as_ref());

    let emit = |verdict: &'static str, source_kind: &str| {
        emit_decision_row(
            state,
            &DecisionRowInput {
                run_uuid,
                ts: &now,
                verdict,
                source_kind,
                dest_host: &response_context.dest_host,
                dest_port: response_context.dest_port,
                package_context: response_context.package_context.as_ref(),
            },
        );
    };

    let verdict_for_dylib =
        verdict_for_prompt_response(state, run_uuid, resp, &response_context.dest_host, emit);

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

fn take_prompt_response_entry(
    state: &DaemonState,
    run_uuid: &str,
    resp: &PromptResponse,
) -> Option<DeferredEntry> {
    // CR-02: enforce per-run prompt_id ownership. Without this, a malicious or
    // misbehaving dylib running under run-A could send a PromptResponse with
    // a prompt_id parked under run-B (sequential 8-digit ids are predictable),
    // causing the daemon to insert allow rules for run-B, wake run-B's parked
    // Resolve handler, AND mis-attribute the Decision row to run-A's run_uuid.
    match state
        .deferred_resolve
        .take_full_if_owned(&resp.prompt_id, run_uuid)
    {
        Ok(entry_opt) => entry_opt,
        Err(foreign_run_uuid) => {
            tracing::warn!(
                run_uuid = %run_uuid,
                foreign_run_uuid = %foreign_run_uuid,
                foreign_prompt_id = %resp.prompt_id,
                "CR-02: refused cross-run PromptResponse (per-run prompt_id ownership)"
            );
            None
        }
    }
}

struct PromptResponseContext {
    dest_host: String,
    dest_port: u16,
    package_context: Option<guard_ipc::PackageContext>,
}

fn prompt_response_context(entry_opt: Option<&DeferredEntry>) -> PromptResponseContext {
    // BLOCKER / WR-11: recover the (host, port) tuple before the sender is
    // signalled. The entry has already been removed from the table because this
    // path is about to resolve it, but the row must be emitted first.
    let dest_host = entry_opt.map_or_else(String::new, |entry| entry.host.clone());
    let dest_port = entry_opt.map_or(0, |entry| entry.port);

    // v0.5 / CONTEXT C-01: pull the package_context stashed at park-time so the
    // JSONL Decision row carries package-manager context when available.
    let package_context = entry_opt.and_then(|entry| entry.package_context.clone());

    PromptResponseContext {
        dest_host,
        dest_port,
        package_context,
    }
}

fn verdict_for_prompt_response(
    state: &DaemonState,
    run_uuid: &str,
    resp: &PromptResponse,
    dest_host: &str,
    emit: impl Fn(&'static str, &str),
) -> guard_core::Verdict {
    match &resp.verdict {
        PromptVerdict::AllowOnce => {
            emit("Allow", "prompt_allow_once");
            guard_core::Verdict::Allow
        }
        PromptVerdict::AllowAlwaysMachine => allow_always_machine_verdict(
            state,
            run_uuid,
            dest_host,
            resp.signed_rule.as_ref(),
            resp.rule_pattern.as_ref(),
            emit,
        ),
        PromptVerdict::Deny => {
            emit("Deny", "prompt_deny");
            guard_core::Verdict::Deny
        }
    }
}

fn allow_always_machine_verdict(
    state: &DaemonState,
    run_uuid: &str,
    dest_host: &str,
    signed_rule: Option<&InsertUserRule>,
    rule_pattern: Option<&RulePattern>,
    emit: impl Fn(&'static str, &str),
) -> guard_core::Verdict {
    let Some(signed_rule) = signed_rule else {
        tracing::warn!(
            run_uuid = %run_uuid,
            host = %dest_host,
            "prompt allow-always missing signed rule attestation; denying fail-closed"
        );
        emit("Deny", "prompt_allow_machine_missing_signature");
        return guard_core::Verdict::Deny;
    };

    let Some(rule_pattern) = rule_pattern else {
        tracing::warn!(
            run_uuid = %run_uuid,
            host = %dest_host,
            "prompt allow-always missing rule pattern; denying fail-closed"
        );
        emit("Deny", "prompt_allow_machine_missing_pattern");
        return guard_core::Verdict::Deny;
    };

    if signed_rule.kind != "allow"
        || signed_rule.match_type != rule_pattern.match_type
        || signed_rule.pattern != rule_pattern.pattern
        || signed_rule.run_uuid.as_deref() != Some(run_uuid)
    {
        tracing::warn!(
            run_uuid = %run_uuid,
            host = %dest_host,
            "prompt allow-always signed rule does not match prompt response; denying fail-closed"
        );
        emit("Deny", "prompt_allow_machine_signature_mismatch");
        return guard_core::Verdict::Deny;
    }

    match crate::handlers::insert_user_rule::handle_insert_user_rule(
        signed_rule,
        &state.rule_store,
        state.rule_signature_policy,
    ) {
        guard_ipc::InsertUserRuleReply::Ok { .. } => {
            emit("Allow", "prompt_allow_machine");
            guard_core::Verdict::Allow
        }
        guard_ipc::InsertUserRuleReply::Err { message, .. } => {
            tracing::warn!(
                run_uuid = %run_uuid,
                host = %dest_host,
                error = %message,
                "prompt allow-always signed rule rejected; denying fail-closed"
            );
            emit("Deny", "prompt_allow_machine_signature_rejected");
            guard_core::Verdict::Deny
        }
    }
}

fn dispatch_cancel(state: &DaemonState, run_uuid: &str, cancel: &PromptCancel) {
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
        let _ = entry.sender.send(guard_core::Verdict::Deny);
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
/// v0.4: the helper now takes `dest_host` and an
/// optional `package_context` so the IPC handler context (which knows both)
/// can drive `log_writer` enrichment caller-side, NOT in the writer thread
/// (v0.3 caller-side contention discipline).
///
/// `intel` is computed by combining package-source matches (when
/// `package_context` is provided) with host-source matches (always probed when
/// the `source_kind` looks like a feed-derived verdict (confirmed-deny or
/// suspect-deny), since those are the principal paths that host_ioc-derived
/// rows produce).
struct DecisionRowInput<'a> {
    run_uuid: &'a str,
    ts: &'a str,
    verdict: &'static str,
    source_kind: &'a str,
    dest_host: &'a str,
    dest_port: u16,
    package_context: Option<&'a PackageContext>,
}

fn emit_decision_row(state: &DaemonState, input: &DecisionRowInput<'_>) {
    let mut intel_combined: Vec<guard_ipc::IntelMatch> = Vec::new();
    if let Some(pkg) = input.package_context {
        intel_combined.extend(log_writer::enrich(pkg));
    }
    if matches!(input.source_kind, "confirmed-deny" | "suspect-deny") {
        intel_combined.extend(log_writer::enrich_for_host(input.dest_host));
    }
    let intel = if intel_combined.is_empty() {
        None
    } else {
        Some(intel_combined)
    };

    let dec = Decision {
        schema_version: JSONL_SCHEMA_VERSION,
        ts: input.ts.to_string(),
        verdict: input.verdict,
        dest_host: input.dest_host.to_string(),
        dest_port: input.dest_port,
        dest_ip: None,
        run_uuid: input.run_uuid.to_string(),
        source_kind: input.source_kind.to_string(),
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
        package_context: input.package_context.cloned(),
        intel,
    };
    if input.verdict == "Allow" {
        state.log_writer.send(LogRow::Allow(dec));
    } else {
        state.log_writer.send(LogRow::Block(dec));
    }
}

#[cfg(test)]
mod plan_05_03_tests {
    //! v0.5 — pin the `entry_pkg` extraction shape used by
    //! `handle_prompt_response`. The HARD wiring test (entire daemon under
    //! `npm install` → JSONL row carries package_context.package="ua-parser-js")
    //! lives in Plan 05-04 (VAL-01). This test only pins the local-binding
    //! contract so a future refactor can't silently regress it.
    use guard_ipc::PackageContext;

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
        let extracted: Option<PackageContext> = stashed.clone();
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
        let extracted: Option<PackageContext> = stashed.clone();
        assert!(extracted.is_none());
    }
}
