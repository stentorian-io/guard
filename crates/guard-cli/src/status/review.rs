//! crates/guard-cli/src/status/review.rs
//!
//! v0.7 — `stt-guard status review [<run_uuid>]`.
//! TTY-required interactive walk-through of the previously-blocked hosts in a
//! given run; refactor target of the v0.1 `approve.rs::run_approve_from_log`.
//!
//! Behavior:
//!   - non-TTY stdin → exit 64 (EX_USAGE) with stderr message.
//!   - when no `<run_uuid>` is given, use
//!     `denial_log::most_recent_run_with_denials`.
//!   - per-host options are (a)/(d)/(s)/(q); single-letter,
//!     case-insensitive; bare Enter defaults to 's' (skip).
//!   - BOTH allow AND deny rules go to machine-wide SQLite
//!     via `insert_user_rule_request` (no project flag here).
//!   - host caps come from `denial_log` constants —
//!     bounded memory regardless of log size.

use std::path::Path;

use crate::denial_log;
use crate::install::launchagent;
use crate::ipc_client;
use crate::tty;
use crate::CliError;

pub fn run(sock: &Path, run_uuid: Option<String>) -> Result<i32, CliError> {
    // TTY-required gate. Refuse to run from a non-interactive
    // stdin so a CI pipeline can't accidentally answer prompts and
    // silently insert allow/deny rules.
    if !tty::stdin_is_tty() {
        eprintln!(
            "stt-guard: status review requires an interactive terminal \
             (run on a developer machine, not in CI)"
        );
        return Ok(64); // EX_USAGE
    }

    let log_path = launchagent::logs_dir().join(guard_core::paths::LOG_FILENAME);

    // Default uuid = most recent run with denials.
    let uuid = match run_uuid {
        Some(u) => u,
        None => match denial_log::most_recent_run_with_denials(&log_path)? {
            Some(u) => u,
            None => {
                println!("No runs with denials found in {}.", log_path.display());
                return Ok(0);
            }
        },
    };

    let blocks = denial_log::filter_block_destinations(&log_path, &uuid)?;
    if blocks.is_empty() {
        println!("No block entries for run {uuid}.");
        return Ok(0);
    }
    println!(
        "Reviewing {} unique blocked host(s) in run {uuid}:",
        blocks.len()
    );

    let mut allowed: u64 = 0;
    let mut denied: u64 = 0;
    let mut skipped: u64 = 0;

    for b in &blocks {
        loop {
            // Order is (a)/(d)/(s)/(q) — destructive options first
            // so users can't fat-finger 'q' when they meant to confirm.
            print!(
                "  {} (port {}) — [a]llow / [d]eny / [s]kip / [q]uit > ",
                b.host, b.port
            );
            std::io::Write::flush(&mut std::io::stdout()).ok();
            let mut line = String::new();
            let bytes_read = std::io::BufRead::read_line(&mut std::io::stdin().lock(), &mut line)
                .map_err(|e| CliError::Other(format!("stdin: {e}")))?;
            // Detect zero-byte reads as EOF (stdin closed mid-session,
            // e.g. TTY redirected to /dev/null after the initial gate). Without
            // this guard, the inner `loop` reprints the prompt at full CPU
            // speed for each remaining host because read_line returns Ok(0)
            // every iteration and the unwrap_or('s') default lets us "break"
            // with skipped+=1, only for the outer for-loop to enter the next
            // host's inner loop with the same EOF state. Treat as user
            // cancellation; report partial tally and exit cleanly.
            // Bare Enter (single '\n') reads 1 byte (the
            // newline), so the existing "Enter = skip" UX is unaffected.
            if bytes_read == 0 {
                println!(
                    "Reviewed {allowed} allow, {denied} deny, \
                     {skipped} skipped (stdin closed)."
                );
                return Ok(0);
            }
            // Bare Enter defaults to 's' (skip).
            let c = line.trim().to_lowercase().chars().next().unwrap_or('s');
            match c {
                'a' => {
                    // Allow rules also go to machine-wide SQLite.
                    let reason = format!("user-approved from review of run {uuid}");
                    ipc_client::insert_user_rule_request_with_origin(
                        sock,
                        "allow",
                        "exact",
                        &b.host,
                        &reason,
                        "review",
                        Some(&uuid),
                    )?;
                    allowed += 1;
                    break;
                }
                'd' => {
                    // Deny rules ALWAYS go to machine-wide.
                    let reason = format!("user-denied from review of run {uuid}");
                    ipc_client::insert_user_rule_request_with_origin(
                        sock,
                        "deny",
                        "exact",
                        &b.host,
                        &reason,
                        "review",
                        Some(&uuid),
                    )?;
                    denied += 1;
                    break;
                }
                's' => {
                    skipped += 1;
                    break;
                }
                'q' => {
                    println!(
                        "Reviewed {allowed} allow, {denied} deny, \
                         {skipped} skipped (quit early)."
                    );
                    return Ok(0);
                }
                _ => println!("  invalid; enter a, d, s, or q"),
            }
        }
    }
    println!("Reviewed {allowed} allow, {denied} deny, {skipped} skipped.");
    Ok(0)
}
