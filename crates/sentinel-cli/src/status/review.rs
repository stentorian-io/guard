//! crates/sentinel-cli/src/status/review.rs
//!
//! Phase 07 plan 03 — `sentinel status review [<run_uuid>]`
//! (CLI-19, CLI-20, D-26..D-30). TTY-required interactive walk-through
//! of the previously-blocked hosts in a given run; refactor target of
//! the v0.1 `approve.rs::run_approve_from_log`.
//!
//! Behavior (D-26..D-30):
//!   - CLI-20: non-TTY stdin → exit 64 (EX_USAGE) with stderr message.
//!   - D-26: when no `<run_uuid>` is given, use
//!     `denial_log::most_recent_run_with_denials`.
//!   - D-27: per-host options are (a)/(d)/(s)/(q); single-letter,
//!     case-insensitive; bare Enter defaults to 's' (skip).
//!   - D-28/D-29: BOTH allow AND deny rules go to machine-wide SQLite
//!     via `insert_user_rule_request` (no project flag here).
//!   - D-30: WR-05 host caps come from `denial_log` constants —
//!     bounded memory regardless of log size.

use std::path::Path;

use crate::denial_log;
use crate::install::launchagent;
use crate::ipc_client;
use crate::tty;
use crate::CliError;

pub fn run(sock: &Path, run_uuid: Option<String>) -> Result<i32, CliError> {
    // CLI-20: TTY-required gate. Refuse to run from a non-interactive
    // stdin so a CI pipeline can't accidentally answer prompts and
    // silently insert allow/deny rules.
    if !tty::stdin_is_tty() {
        eprintln!(
            "sentinel: status review requires an interactive terminal \
             (run on a developer machine, not in CI)"
        );
        return Ok(64); // EX_USAGE
    }

    let log_path = launchagent::logs_dir().join("sentinel.log");

    // D-26: default uuid = most recent run with denials.
    let uuid = match run_uuid {
        Some(u) => u,
        None => match denial_log::most_recent_run_with_denials(&log_path)? {
            Some(u) => u,
            None => {
                println!(
                    "No runs with denials found in {}.",
                    log_path.display()
                );
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
            // D-27: order is (a)/(d)/(s)/(q) — destructive options first
            // so users can't fat-finger 'q' when they meant to confirm.
            print!(
                "  {} (port {}) — [a]llow / [d]eny / [s]kip / [q]uit > ",
                b.host, b.port
            );
            std::io::Write::flush(&mut std::io::stdout()).ok();
            let mut line = String::new();
            std::io::BufRead::read_line(&mut std::io::stdin().lock(), &mut line)
                .map_err(|e| CliError::Other(format!("stdin: {e}")))?;
            // D-27: bare Enter defaults to 's' (skip).
            let c = line.trim().to_lowercase().chars().next().unwrap_or('s');
            match c {
                'a' => {
                    // D-29: allow rules also go to machine-wide SQLite.
                    let reason = format!("user-approved from review of run {uuid}");
                    ipc_client::insert_user_rule_request(sock, "allow", "exact", &b.host, &reason)?;
                    allowed += 1;
                    break;
                }
                'd' => {
                    // D-28: deny rules ALWAYS go to machine-wide.
                    let reason = format!("user-denied from review of run {uuid}");
                    ipc_client::insert_user_rule_request(sock, "deny", "exact", &b.host, &reason)?;
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
