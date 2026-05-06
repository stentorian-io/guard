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
use std::path::PathBuf;
use std::sync::Arc;

use serde::{Deserialize, Serialize};

use sentinel_ipc::{PromptCancel, PromptRequest, PromptResponse, PromptVerdict};

use crate::ipc_server::DaemonState;
use crate::log_writer::{
    now_rfc3339, Decision, GapRecord, LogRow, ProcessCtxLog, RootCtxLog, JSONL_SCHEMA_VERSION,
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
    let _ = std::thread::Builder::new()
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
    state.deferred_resolve.drain_for_run(&run_uuid);
    state.process_tree.take_prompt_channel(&run_uuid);
    let _ = state.baseline_staging.take(&run_uuid);
    tracing::debug!(run_uuid = %run_uuid, "prompt_channel thread exit");
}

fn dispatch_response(state: &DaemonState, run_uuid: &str, resp: PromptResponse) {
    let now = now_rfc3339();
    // Determine verdict + side-effects, THEN signal the parked oneshot.
    let verdict_for_dylib = match &resp.verdict {
        PromptVerdict::AllowOnce => {
            emit_decision_row(state, run_uuid, &now, "Allow", "prompt_allow_once");
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
            emit_decision_row(state, run_uuid, &now, "Allow", "prompt_allow_machine");
            sentinel_core::Verdict::Allow
        }
        PromptVerdict::AllowAlwaysProject => {
            // CR-08: side-effects can fail (disk full on persist, trust update
            // on a poisoned rule store, no project_toml_path per CR-05). The
            // user's connection should still go through — downgrade to a one-
            // shot Allow with a distinct decision-row source_kind so the audit
            // log makes the partial-failure path obvious post-hoc.
            // CR-05: append_rule_and_update_trust now hard-fails when
            // project_toml_path is None instead of writing to an arbitrary
            // location, which trips this same downgrade path.
            let mut source_kind = "prompt_allow_project";
            if let Some(rp) = resp.rule_pattern.as_ref() {
                if let Err(e) = append_rule_and_update_trust(
                    state,
                    run_uuid,
                    &rp.match_type,
                    &rp.pattern,
                ) {
                    tracing::warn!(
                        error = %e,
                        run_uuid = %run_uuid,
                        "AllowAlwaysProject side-effects failed; downgrading to AllowOnce"
                    );
                    source_kind = "prompt_allow_once_after_persist_failure";
                }
            }
            emit_decision_row(state, run_uuid, &now, "Allow", source_kind);
            sentinel_core::Verdict::Allow
        }
        PromptVerdict::Deny => {
            emit_decision_row(state, run_uuid, &now, "Deny", "prompt_deny");
            sentinel_core::Verdict::Deny
        }
    };

    // Signal the parked Resolve handler thread.
    // WR-11: use take_full so we know the (run_uuid, host, port) and can
    // forget() the dedup entry. Otherwise PromptDedup entries pile up over
    // the run's lifetime and a re-attempt to the same host within the 5s
    // dedup window would reuse the dead prompt_id.
    if let Some(entry) = state.deferred_resolve.take_full(&resp.prompt_id) {
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
    // WR-11: same as dispatch_response — clear the dedup entry on cancel.
    if let Some(entry) = state.deferred_resolve.take_full(&cancel.prompt_id) {
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

fn emit_decision_row(
    state: &DaemonState,
    run_uuid: &str,
    ts: &str,
    verdict: &'static str,
    source_kind: &str,
) {
    let dec = Decision {
        schema_version: JSONL_SCHEMA_VERSION,
        ts: ts.to_string(),
        verdict,
        dest_host: String::new(),
        dest_port: 0,
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
        package_context: None,
        intel: None,
    };
    if verdict == "Allow" {
        state.log_writer.send(LogRow::Allow(dec));
    } else {
        state.log_writer.send(LogRow::Block(dec));
    }
}

/// Append a new [[rules]] entry to the run's closest .sentinel.toml AND fire the
/// daemon-internal trust update inline (re-hash the file on disk, update the
/// trusted_policy_files table). This makes the new rule active for any subsequent
/// connect() call in the same run — including the one currently parked on this prompt.
fn append_rule_and_update_trust(
    state: &DaemonState,
    run_uuid: &str,
    match_type: &str,
    pattern: &str,
) -> std::io::Result<()> {
    let run = match state.process_tree.get_run(run_uuid) {
        Some(r) => r,
        None => return Err(std::io::Error::other("no run record")),
    };
    // CR-05: refuse to auto-create policy files in arbitrary locations. When
    // `project_toml_path` is None, the prior code derived a target from the
    // snapshot path (state_dir/.sentinel.toml). Combined with auto-trust on
    // creation, that let an AllowAlwaysProject verdict deposit policy outside
    // any user project tree. Now we hard-fail; the caller (dispatch_response)
    // logs the failure and downgrades the verdict to AllowOnce, which has no
    // persistent side effects.
    let target_path = match run.project_toml_path.as_deref() {
        Some(p) => PathBuf::from(p),
        None => {
            return Err(std::io::Error::other(
                "AllowAlwaysProject refused: no .sentinel.toml found for this run",
            ));
        }
    };
    let existing =
        std::fs::read_to_string(&target_path).unwrap_or_else(|_| "version = 1\n".into());
    let new_content = sentinel_core::policy_file_writer::append_rule(
        &existing,
        "allow",
        match_type,
        pattern,
        &format!("user-approved via prompt run {run_uuid}"),
    )
    .map_err(|e| std::io::Error::other(format!("toml_edit: {e}")))?;
    let parent = target_path
        .parent()
        .ok_or_else(|| std::io::Error::other("no parent"))?;
    std::fs::create_dir_all(parent).ok();
    let mut tf = tempfile::NamedTempFile::new_in(parent)?;
    use std::io::Write;
    tf.write_all(new_content.as_bytes())?;
    tf.as_file().sync_all()?;
    tf.persist(&target_path)
        .map_err(|e| std::io::Error::other(format!("persist: {e}")))?;

    // Daemon-internal trust update: re-hash the file on disk.
    // T-02-06a-01 invariant: daemon RE-HASHES the file on disk; wire-claimed sha256 NOT trusted.
    use sha2::{Digest, Sha256};
    let on_disk = std::fs::read(&target_path)?;
    let sha = format!("{:x}", Sha256::digest(&on_disk));
    let canonical =
        std::fs::canonicalize(&target_path).unwrap_or_else(|_| target_path.clone());
    if let Err(e) = state
        .rule_store
        .insert_trusted(&canonical.display().to_string(), &sha, "prompt")
    {
        tracing::warn!(error = %e, "trust update failed after AllowAlwaysProject append");
    }
    // Update the run's project_toml_path if it was None before (newly-created file).
    state
        .process_tree
        .set_run_project_toml_path(run_uuid, Some(canonical.display().to_string()));
    Ok(())
}
