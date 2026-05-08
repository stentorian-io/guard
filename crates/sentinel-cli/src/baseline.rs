//! crates/sentinel-cli/src/baseline.rs
//!
//! Phase 3 plan 03-13 (Phase 06 rename) — `sentinel --learn <cmd>` exit flow (POL-04 / D-58, D-59, D-60).
//! BLOCKER #2: D-60 3-way diff + 4-choice merge menu when existing .sentinel.toml has rules.

use std::collections::HashSet;
use std::io::{IsTerminal, Write, BufRead};
use std::path::{Path, PathBuf};

use sentinel_ipc::{BaselineCommitReply, ProposedRule};

use crate::CliError;

pub fn run_baseline_commit(sock: &Path, run_uuid: &str) -> Result<(), CliError> {
    let reply = crate::ipc_client::baseline_commit_request(sock, run_uuid)?;
    let (proposed, existing_path_opt, existing_content_opt) = match reply {
        BaselineCommitReply::Ok {
            proposed_rules,
            existing_toml_path,
            existing_toml_content,
            ..
        } => (proposed_rules, existing_toml_path, existing_toml_content),
        BaselineCommitReply::Err { message, .. } => {
            return Err(CliError::Other(format!("BaselineCommit Err: {message}")));
        }
    };

    if proposed.is_empty() {
        println!("Baseline: no entries recorded for run {run_uuid}.");
        return Ok(());
    }

    let target = existing_path_opt
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            std::env::current_dir()
                .unwrap_or_else(|_| PathBuf::from("."))
                .join(".sentinel.toml")
        });
    let existing = existing_content_opt.unwrap_or_else(|| "version = 1\n".to_string());

    let has_existing_rules = existing.contains("[[rules]]");

    let new_content = if has_existing_rules {
        run_three_way_merge(&existing, &proposed, &target)?
    } else {
        let rules_for_writer: Vec<(&str, &str, &str, &str)> = proposed
            .iter()
            .map(|r| ("allow", r.match_type.as_str(), r.pattern.as_str(), r.reason.as_str()))
            .collect();
        let new_content =
            sentinel_core::policy_file_writer::append_rules(&existing, &rules_for_writer)
                .map_err(|e| CliError::Other(format!("policy_file_writer: {e}")))?;
        println!("Baseline: {} rule(s) recorded for run {run_uuid}.", proposed.len());
        println!("Target: {}", target.display());
        println!("Diff:");
        let diff = similar::TextDiff::from_lines(&existing, &new_content);
        let unified = diff
            .unified_diff()
            .header("a/.sentinel.toml", "b/.sentinel.toml")
            .to_string();
        for line in unified.lines() {
            println!("  {line}");
        }
        if !confirm_yn("Apply baseline?")? {
            println!("Aborted.");
            return Ok(());
        }
        new_content
    };

    // Atomic write.
    let parent = target
        .parent()
        .ok_or_else(|| CliError::Other(".sentinel.toml has no parent".into()))?;
    std::fs::create_dir_all(parent).ok();
    let mut tf = tempfile::NamedTempFile::new_in(parent)
        .map_err(|e| CliError::Other(format!("tempfile: {e}")))?;
    tf.write_all(new_content.as_bytes())
        .map_err(|e| CliError::Other(format!("write: {e}")))?;
    tf.as_file().sync_all().ok();
    tf.persist(&target)
        .map_err(|e| CliError::Other(format!("persist: {e}")))?;

    use sha2::{Digest, Sha256};
    let canonical = target
        .canonicalize()
        .unwrap_or_else(|_| target.clone());
    let sha = format!("{:x}", Sha256::digest(new_content.as_bytes()));
    crate::ipc_client::trust_policy_request(
        sock,
        &canonical.display().to_string(),
        &sha,
    )?;
    println!(
        "Baseline committed; trust updated for sha256={}.",
        &sha[..12]
    );
    Ok(())
}

/// Build "merged": existing + only proposed rules whose (match_type, pattern) is NOT in existing.
pub(crate) fn build_merged(
    existing: &str,
    proposed: &[ProposedRule],
) -> Result<String, CliError> {
    let existing_keys = extract_existing_rule_keys(existing);
    let to_append: Vec<(&str, &str, &str, &str)> = proposed
        .iter()
        .filter(|r| !existing_keys.contains(&(r.match_type.clone(), r.pattern.clone())))
        .map(|r| ("allow", r.match_type.as_str(), r.pattern.as_str(), r.reason.as_str()))
        .collect();
    sentinel_core::policy_file_writer::append_rules(existing, &to_append)
        .map_err(|e| CliError::Other(format!("policy_file_writer: {e}")))
}

/// Build "proposed-only": stub + ALL proposed rules.
pub(crate) fn build_proposed_only(proposed: &[ProposedRule]) -> Result<String, CliError> {
    let stub = "version = 1\n";
    let rules: Vec<(&str, &str, &str, &str)> = proposed
        .iter()
        .map(|r| ("allow", r.match_type.as_str(), r.pattern.as_str(), r.reason.as_str()))
        .collect();
    sentinel_core::policy_file_writer::append_rules(stub, &rules)
        .map_err(|e| CliError::Other(format!("policy_file_writer: {e}")))
}

/// Extract `(match_type, pattern)` keys from every `[[rules]]` entry in a
/// `.sentinel.toml` body. Public for the unit test in
/// tests/baseline_three_way_merge.rs.
///
/// WR-06: parses with `toml_edit::DocumentMut` so we honor real TOML
/// structure — escape sequences in strings, multiline strings, mixed-case
/// neighboring keys (`match_label`, `pattern_v2` no longer collide with
/// `match`/`pattern`), and array-of-tables semantics. Returns an empty set on
/// parse failure rather than guessing — callers compare against this set for
/// dedup, so a misparsed key would manifest as an unwanted duplicate which is
/// strictly worse than a missed dedup.
pub fn extract_existing_rule_keys(content: &str) -> HashSet<(String, String)> {
    let mut keys = HashSet::new();
    let doc = match content.parse::<toml_edit::DocumentMut>() {
        Ok(d) => d,
        Err(_) => return keys,
    };
    let Some(rules_item) = doc.get("rules") else { return keys };
    let Some(arr) = rules_item.as_array_of_tables() else { return keys };
    for table in arr.iter() {
        let m = table
            .get("match")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());
        let p = table
            .get("pattern")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());
        if let (Some(m), Some(p)) = (m, p) {
            keys.insert((m, p));
        }
    }
    keys
}

fn run_three_way_merge(
    existing: &str,
    proposed: &[ProposedRule],
    target: &Path,
) -> Result<String, CliError> {
    let proposed_text = build_proposed_only(proposed)?;
    let merged_text = build_merged(existing, proposed)?;

    println!(
        "Baseline: {} rule(s) recorded; existing .sentinel.toml has rules.",
        proposed.len()
    );
    println!("Target: {}", target.display());
    println!("\n=== existing → proposed (what's NEW in proposed-only) ===");
    print_unified_diff(existing, &proposed_text, "existing", "proposed");
    println!("\n=== existing → merged (what MERGE would do) ===");
    print_unified_diff(existing, &merged_text, "existing", "merged");
    println!("\n=== proposed → merged (what MERGE KEEPS from existing) ===");
    print_unified_diff(&proposed_text, &merged_text, "proposed", "merged");

    if !std::io::stdin().is_terminal() {
        return Err(CliError::Other(
            "non-TTY: cannot prompt for replace/merge/abort; baseline aborted".into(),
        ));
    }

    loop {
        let choice = dialoguer::Select::with_theme(&dialoguer::theme::ColorfulTheme::default())
            .with_prompt("Choose action")
            .items(&[
                "Replace existing with proposed only",
                "Merge (deduped union of existing + proposed)",
                "Abort",
                "Show full files side-by-side",
            ])
            .default(1)
            .interact()
            .map_err(|e| CliError::Other(format!("dialoguer: {e}")))?;
        match choice {
            0 => {
                // CR-04: Replace destroys hand-curated rules, deny rules, and
                // comments authored by the user. Refuse on non-TTY (already
                // guarded above but defensive — a future caller might bypass
                // the outer TTY check) and ALWAYS write a timestamped backup
                // of the prior file before returning the replacement text.
                if !std::io::stdin().is_terminal() {
                    return Err(CliError::Other(
                        "non-TTY: refusing Replace; baseline aborted".into(),
                    ));
                }
                if target.exists() {
                    let backup = backup_path(target);
                    match std::fs::copy(target, &backup) {
                        Ok(_) => {
                            eprintln!(
                                "Wrote backup of prior policy to {} before Replace.",
                                backup.display()
                            );
                        }
                        Err(e) => {
                            return Err(CliError::Other(format!(
                                "Replace aborted — could not write backup at {}: {e}",
                                backup.display()
                            )));
                        }
                    }
                }
                return Ok(proposed_text);
            }
            1 => return Ok(merged_text),
            2 => return Err(CliError::Other("aborted by user".into())),
            3 => {
                println!("\n--- existing ---\n{existing}");
                println!("\n--- merged ---\n{merged_text}");
                continue;
            }
            _ => unreachable!(),
        }
    }
}

/// CR-04: derive a timestamped backup path from the target. The timestamp uses
/// chrono's UTC formatter (already a transitive dep through sentinel-daemon)
/// for a sortable suffix.
fn backup_path(target: &Path) -> PathBuf {
    let stamp = chrono::Utc::now().format("%Y%m%dT%H%M%SZ").to_string();
    let mut name = target
        .file_name()
        .map(|s| s.to_os_string())
        .unwrap_or_else(|| std::ffi::OsString::from(".sentinel.toml"));
    name.push(".bak.");
    name.push(stamp);
    target
        .parent()
        .map(|p| p.join(&name))
        .unwrap_or_else(|| PathBuf::from(name))
}

fn print_unified_diff(a: &str, b: &str, a_label: &str, b_label: &str) {
    let diff = similar::TextDiff::from_lines(a, b);
    let unified = diff.unified_diff().header(a_label, b_label).to_string();
    for line in unified.lines() {
        println!("  {line}");
    }
}

fn confirm_yn(prompt: &str) -> Result<bool, CliError> {
    if !std::io::stdin().is_terminal() {
        return Err(CliError::Other(format!(
            "{prompt} (TTY required for confirmation; baseline aborted)"
        )));
    }
    print!("{prompt} [y/N] ");
    std::io::stdout()
        .flush()
        .map_err(|e| CliError::Other(format!("stdout: {e}")))?;
    let mut line = String::new();
    std::io::stdin()
        .lock()
        .read_line(&mut line)
        .map_err(|e| CliError::Other(format!("stdin: {e}")))?;
    Ok(matches!(
        line.trim().to_lowercase().as_str(),
        "y" | "yes"
    ))
}
