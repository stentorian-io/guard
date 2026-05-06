//! `sentinel trust-policy <path>` subcommand (D-38).
//!
//! Reads the file, displays the rules in tabular plain text, prompts the user
//! at the terminal for y/n confirmation, computes SHA-256, and sends a
//! `TrustPolicy` IPC to the daemon. Daemon-side defense-in-depth re-hashes
//! before inserting (T-02-06a-01; handler in plan 02-06a).
//!
//! UX: matches `git`/`brew`-style y/n prompts. Non-TTY callers (CI / scripts)
//! get a fail-closed diagnostic — T-02-06b-02 mitigation. CI must rely on a
//! pre-configured trust state set up interactively, not on auto-trusting via
//! piped `yes`.

use crate::CliError;
use crate::ipc_client::trust_policy_request;
use sentinel_core::policy_file::{SentinelToml, parse};
use sha2::{Digest, Sha256};
use std::io::{BufRead, IsTerminal, Write};
use std::path::Path;

pub fn run_trust_policy(sock: &Path, toml_path: &Path) -> Result<(), CliError> {
    // 1. Canonicalize + read. Canonicalize first so the daemon sees the same
    //    absolute path the user reviewed (no symlink ambiguity); the daemon
    //    re-hashes via the same canonical path.
    let canonical = toml_path
        .canonicalize()
        .map_err(|e| CliError::Other(format!("canonicalize {}: {e}", toml_path.display())))?;
    let bytes = std::fs::read(&canonical)
        .map_err(|e| CliError::Other(format!("read {}: {e}", canonical.display())))?;
    let content = std::str::from_utf8(&bytes)
        .map_err(|e| CliError::Other(format!("not UTF-8: {e}")))?;

    // 2. Parse + display. We display BEFORE the TTY check so the user always
    //    sees what they would have been asked to trust — even in non-TTY
    //    contexts where we then refuse to prompt.
    let parsed = parse(content).map_err(|e| CliError::Other(format!("parse: {e}")))?;
    println!("Reviewing {}:", canonical.display());
    println!("  version = {}", parsed.version);
    display_rules(&parsed);

    // 3. Prompt y/n — fail-closed in non-TTY (T-02-06b-02).
    if !std::io::stdin().is_terminal() {
        return Err(CliError::Other(
            "trust-policy requires a terminal (TTY) for y/n confirmation; refusing to auto-trust".into(),
        ));
    }
    if !confirm("Trust this file?")? {
        println!("Aborted — file NOT trusted.");
        return Ok(());
    }

    // 4. Compute SHA-256 + IPC. The daemon re-hashes the file at handler time
    //    and rejects if our claimed hash disagrees (T-02-06a-01) — defense in
    //    depth even though we just hashed the same bytes ourselves.
    let sha = format!("{:x}", Sha256::digest(&bytes));
    trust_policy_request(sock, &canonical.display().to_string(), &sha)?;
    println!(
        "Trusted. Future `sentinel run` invocations from {} will honor these rules.",
        canonical.display()
    );
    Ok(())
}

fn display_rules(toml: &SentinelToml) {
    println!(
        "{:<8} {:<8} {:<50} {}",
        "kind", "match", "pattern", "reason"
    );
    println!("{}", "-".repeat(100));
    for r in &toml.rules {
        println!(
            "{:<8} {:<8} {:<50} {}",
            format!("{:?}", r.kind).to_lowercase(),
            format!("{:?}", r.match_type).to_lowercase(),
            r.pattern,
            r.reason,
        );
    }
}

fn confirm(prompt: &str) -> Result<bool, CliError> {
    print!("{prompt} [y/N] ");
    std::io::stdout()
        .flush()
        .map_err(|e| CliError::Other(format!("stdout flush: {e}")))?;
    let mut line = String::new();
    std::io::stdin()
        .lock()
        .read_line(&mut line)
        .map_err(|e| CliError::Other(format!("stdin read: {e}")))?;
    Ok(matches!(line.trim().to_lowercase().as_str(), "y" | "yes"))
}
