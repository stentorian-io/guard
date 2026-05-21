//! crates/guard-cli/src/run_orchestrator.rs
//!
//! Wrap-mode end-to-end orchestrator:
//! V3 PrepareSnapshot + prompt channel + spawn + wait.
//! SIGINT handler is registered here.

use std::ffi::OsString;
use std::io::IsTerminal;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use crate::CliError;

pub fn run(
    sock: &Path,
    state_dir: &Path,
    command: Vec<OsString>,
    learn_mode: bool,
) -> Result<i32, CliError> {
    let _ = state_dir; // reserved for future use
    let cwd = std::env::current_dir().map_err(|e| CliError::Other(format!("cwd: {e}")))?;
    let is_tty = std::io::stdin().is_terminal();

    let outcome = crate::ipc_client::prepare_snapshot_v3(sock, &cwd, is_tty, learn_mode)?;
    let manifest_path = outcome.manifest_path.clone();
    let run_uuid = outcome.run_uuid.clone();

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
    let inflight_handle: Option<crate::prompt_channel::InflightPrompts> = if is_tty {
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
        crate::spawn::spawn_wrapped_with_pgid(&command, &manifest_path, &run_uuid)?;

    // Restore the RegisterRoot delegation that was lost in the v0.3
    // refactor (commit d020752 — extracted run_orchestrator from main.rs and
    // dropped the audit_token + register_root_with_daemon call sites).
    //
    // Without this, the daemon's `is_tracked(peer_token)` returns false for
    // every IPC the wrapped child sends (DylibLoaded, ForkEvent, ExecEvent,
    // EnvNotPropagatedGap). The TREE-06 e2e tests, the pm_env capture e2e
    // tests, and any other test that depends on
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
    let root_pm_env = capture_pm_env_from_current_env();
    crate::ipc_client::register_root_for_run_with_pm_env_with_daemon(
        sock,
        token,
        &run_uuid,
        root_pm_env,
    )?;

    // ALWAYS install the SIGINT handler so Ctrl-C reliably propagates to the
    // wrapped child's process group, even when the prompt channel is
    // unavailable (non-TTY, learn mode, schema skew, transient daemon error).
    // When `inflight_handle` is None we install with an empty in-flight
    // registry; `handle_sigint` tolerates an absent channel and a zero-length
    // set, falling through to the load-bearing `killpg`.
    let inflight_for_sigint = inflight_handle.clone().unwrap_or_default();
    let _sigint_handle =
        crate::sigint_handler::install(inflight_for_sigint, Arc::clone(&shared_channel), pgid)?;

    // Render-loop thread (interactive runs, including learn-mode for
    // SuspectDeny prompts).
    //
    // The thread owns the `PromptReader` directly and reads without
    // holding the SharedChannel mutex. Writes (`answer`/`cancel`) go through
    // the SharedChannel mutex which is also held briefly by the SIGINT
    // handler — but never simultaneously with a blocking read.
    let stop_flag = Arc::new(AtomicBool::new(false));
    let render_shutdown = prompt_reader
        .as_ref()
        .map(|reader| reader.shutdown_handle())
        .transpose()?;
    let render_handle = if let Some(reader) = prompt_reader.take() {
        let shared = Arc::clone(&shared_channel);
        let stop = Arc::clone(&stop_flag);
        Some(
            std::thread::Builder::new()
                .name("guard-prompt-render".into())
                .spawn(move || render_loop(reader, shared, stop))
                .map_err(|e| CliError::Other(format!("render thread: {e}")))?,
        )
    } else {
        None
    };

    // Wait for child.
    let exit_status = child
        .wait()
        .map_err(|e| CliError::Other(format!("wait: {e}")))?;
    let exit_code = exit_status.code().unwrap_or(1);

    // Drop the SharedChannel writer half and explicitly shut down the
    // render reader clone so a blocked `read_frame` wakes up before join.
    // Dropping only the writer clone is insufficient: the render thread owns a
    // separate cloned UnixStream that can remain parked in recvfrom forever.
    if let Ok(mut g) = shared_channel.lock() {
        *g = None;
    }
    stop_flag.store(true, Ordering::SeqCst);
    if let Some(stream) = render_shutdown.as_ref() {
        crate::prompt_channel::PromptReader::shutdown(stream);
    }
    if let Some(h) = render_handle {
        let _ = h.join();
    }

    if learn_mode {
        present_learn_review(sock, &run_uuid);
    }

    Ok(exit_code)
}

fn present_learn_review(sock: &Path, run_uuid: &str) {
    let proposed = match crate::ipc_client::baseline_commit_request(sock, run_uuid) {
        Ok(rules) => rules,
        Err(e) => {
            tracing::warn!(error = %e, "baseline commit failed; no learn-mode review");
            return;
        }
    };
    if proposed.is_empty() {
        eprintln!("\nstt-guard --learn: no new hosts observed during this run.");
        return;
    }
    eprintln!(
        "\nstt-guard --learn: {} host(s) observed. Review each to create rules:\n",
        proposed.len()
    );

    let mut allowed: u64 = 0;
    let mut denied: u64 = 0;
    let mut skipped: u64 = 0;

    for rule in &proposed {
        loop {
            eprint!("  {} — [a]llow / [d]eny / [s]kip / [q]uit > ", rule.pattern);
            std::io::Write::flush(&mut std::io::stderr()).ok();
            let mut line = String::new();
            let bytes_read =
                std::io::BufRead::read_line(&mut std::io::stdin().lock(), &mut line).unwrap_or(0);
            if bytes_read == 0 {
                eprintln!(
                    "Learn review: {allowed} allow, {denied} deny, {skipped} skipped (stdin closed)."
                );
                return;
            }
            let c = line.trim().to_lowercase().chars().next().unwrap_or('s');
            match c {
                'a' => {
                    let reason = format!("user-approved from learn run {run_uuid}");
                    match crate::ipc_client::insert_user_rule_request(
                        sock,
                        "allow",
                        &rule.match_type,
                        &rule.pattern,
                        &reason,
                    ) {
                        Ok(_) => allowed += 1,
                        Err(e) => eprintln!("    failed to insert allow rule: {e}"),
                    }
                    break;
                }
                'd' => {
                    let reason = format!("user-denied from learn run {run_uuid}");
                    match crate::ipc_client::insert_user_rule_request(
                        sock,
                        "deny",
                        &rule.match_type,
                        &rule.pattern,
                        &reason,
                    ) {
                        Ok(_) => denied += 1,
                        Err(e) => eprintln!("    failed to insert deny rule: {e}"),
                    }
                    break;
                }
                's' => {
                    skipped += 1;
                    break;
                }
                'q' => {
                    eprintln!(
                        "Learn review: {allowed} allow, {denied} deny, {skipped} skipped (quit early)."
                    );
                    return;
                }
                _ => eprintln!("  invalid; enter a, d, s, or q"),
            }
        }
    }
    eprintln!("Learn review: {allowed} allow, {denied} deny, {skipped} skipped.");
}

fn capture_pm_env_from_current_env() -> Vec<(String, String)> {
    use guard_core::env_filter;

    let mut out = Vec::new();
    let mut total = 0usize;
    for (key, value) in std::env::vars() {
        if env_filter::is_secret_key(&key) {
            continue;
        }
        if !env_filter::is_pm_env_key(&key) {
            continue;
        }
        let value = env_filter::truncate_value(&value).to_string();
        let pair_size = key.len() + value.len() + 2;
        if total + pair_size > guard_ipc::ExecEvent::MAX_PM_ENV_BYTES {
            break;
        }
        total += pair_size;
        out.push((key, value));
    }
    out
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
