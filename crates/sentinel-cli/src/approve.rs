//! crates/sentinel-cli/src/approve.rs
//!
//! Phase 3 plan 03-11 — `sentinel approve` (CLI-04).

use std::io::{IsTerminal, Write, BufRead};
use std::path::{Path, PathBuf};

use crate::CliError;

pub struct ApproveArgs {
    pub pattern: Option<String>,
    pub suffix: bool,
    pub project: bool,
    pub from_log: Option<String>,
    pub yes: bool,
}

pub fn run_approve(sock: &Path, args: ApproveArgs) -> Result<i32, CliError> {
    if let Some(uuid) = args.from_log.as_deref() {
        return run_approve_from_log(sock, uuid, args.yes);
    }
    let pattern = args.pattern.as_deref().ok_or_else(|| {
        CliError::Other("usage: sentinel approve <hostname> | --suffix <pattern> | --from-log <run_uuid>".into())
    })?;
    if pattern.trim().is_empty() {
        return Err(CliError::Other("pattern must be non-empty".into()));
    }
    let match_type = if args.suffix { "suffix" } else { "exact" };
    if args.suffix && !pattern.starts_with('.') {
        return Err(CliError::Other(
            "--suffix patterns must start with a dot (e.g. .example.com)".into()
        ));
    }
    let reason = format!("user-approved {}", today_yyyymmdd());

    if args.project {
        run_approve_project(sock, "allow", match_type, pattern, &reason, args.yes)
    } else {
        run_approve_machine(sock, "allow", match_type, pattern, &reason, args.yes)
    }
}

fn run_approve_machine(
    sock: &Path, kind: &str, match_type: &str, pattern: &str, reason: &str, yes: bool,
) -> Result<i32, CliError> {
    println!("kind={kind} match_type={match_type} pattern={pattern} reason={reason}");
    println!("scope: machine-wide (SQLite)");
    if !yes && !confirm("Approve this rule?")? { return Ok(0); }
    let rule_id = crate::ipc_client::insert_user_rule_request(sock, kind, match_type, pattern, reason)?;
    println!("Rule id={rule_id} added.");
    Ok(0)
}

fn run_approve_project(
    sock: &Path, kind: &str, match_type: &str, pattern: &str, reason: &str, yes: bool,
) -> Result<i32, CliError> {
    let cwd = std::env::current_dir().map_err(|e| CliError::Other(format!("cwd: {e}")))?;
    let target = locate_or_default_sentinel_toml(&cwd)?;
    let existing = std::fs::read_to_string(&target).unwrap_or_else(|_| "version = 1\n".to_string());
    let new_content = sentinel_core::policy_file_writer::append_rule(
        &existing, kind, match_type, pattern, reason,
    ).map_err(|e| CliError::Other(format!("toml_edit: {e}")))?;

    println!("Target: {}", target.display());
    println!("Diff:");
    let diff = similar::TextDiff::from_lines(&existing, &new_content);
    for line in diff.unified_diff().header("a/.sentinel.toml", "b/.sentinel.toml").to_string().lines() {
        println!("  {line}");
    }
    if !yes && !confirm("Append rule and update trust?")? { return Ok(0); }

    // Atomic write.
    let parent = target.parent().ok_or_else(|| CliError::Other(".sentinel.toml has no parent".into()))?;
    std::fs::create_dir_all(parent).ok();
    let mut tf = tempfile::NamedTempFile::new_in(parent)
        .map_err(|e| CliError::Other(format!("tempfile: {e}")))?;
    tf.write_all(new_content.as_bytes()).map_err(|e| CliError::Other(format!("write: {e}")))?;
    tf.as_file().sync_all().ok();
    tf.persist(&target).map_err(|e| CliError::Other(format!("persist: {e}")))?;

    // Trust the new (path, sha256) tuple via Phase 2 TrustPolicy IPC.
    use sha2::{Digest, Sha256};
    let canonical_path = target.canonicalize().unwrap_or_else(|_| target.clone());
    let sha = format!("{:x}", Sha256::digest(new_content.as_bytes()));
    crate::ipc_client::trust_policy_request(
        sock, &canonical_path.display().to_string(), &sha,
    )?;
    println!("Rule appended; trust updated for sha256={}.", &sha[..12]);
    Ok(0)
}

fn locate_or_default_sentinel_toml(cwd: &Path) -> Result<PathBuf, CliError> {
    // Walk up looking for .sentinel.toml; stop at .git boundary or depth 8 (mirror Phase 2 D-36).
    let mut current = cwd.canonicalize().unwrap_or_else(|_| cwd.to_path_buf());
    for _ in 0..8 {
        let candidate = current.join(".sentinel.toml");
        if candidate.is_file() { return Ok(candidate); }
        if current.join(".git").exists() {
            // boundary: no .sentinel.toml found within this repo — create in cwd
            return Ok(cwd.join(".sentinel.toml"));
        }
        match current.parent() {
            Some(p) => current = p.to_path_buf(),
            None => break,
        }
    }
    Ok(cwd.join(".sentinel.toml"))
}

fn confirm(prompt: &str) -> Result<bool, CliError> {
    if !std::io::stdin().is_terminal() {
        return Err(CliError::Other(format!(
            "{prompt} (TTY required for confirmation; pass --yes to skip)"
        )));
    }
    print!("{prompt} [y/N] ");
    std::io::stdout().flush().map_err(|e| CliError::Other(format!("stdout: {e}")))?;
    let mut line = String::new();
    std::io::stdin().lock().read_line(&mut line).map_err(|e| CliError::Other(format!("stdin: {e}")))?;
    Ok(matches!(line.trim().to_lowercase().as_str(), "y" | "yes"))
}

fn today_yyyymmdd() -> String {
    // Use simple system time approach to avoid chrono dependency in sentinel-cli.
    // Format: YYYY-MM-DD
    use std::time::{SystemTime, UNIX_EPOCH};
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    // Simple date calculation from Unix timestamp.
    let days_since_epoch = secs / 86400;
    // Compute year/month/day from days since 1970-01-01.
    let (y, m, d) = days_to_ymd(days_since_epoch);
    format!("{y:04}-{m:02}-{d:02}")
}

fn days_to_ymd(days: u64) -> (u64, u64, u64) {
    // Algorithm: http://howardhinnant.github.io/date_algorithms.html (civil_from_days)
    let z = days + 719468;
    let era = z / 146097;
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    (y, m, d)
}

pub(crate) fn run_approve_from_log(sock: &Path, uuid: &str, yes: bool) -> Result<i32, CliError> {
    let active = crate::install::launchagent::logs_dir().join("sentinel.log");
    let blocks = filter_block_destinations(&active, uuid)?;
    if blocks.is_empty() {
        println!("No block entries found for run_uuid={uuid} in {}.", active.display());
        return Ok(0);
    }

    println!("Found {} unique blocked host(s) in run {uuid}:", blocks.len());
    for (i, b) in blocks.iter().enumerate() {
        println!("  [{}] {} (port {})  source_kind={}", i + 1, b.host, b.port, b.source_kind);
    }

    let mut approved = 0u64;
    let mut skipped = 0u64;
    for b in &blocks {
        let prompt = format!("Approve {} (port {})?", b.host, b.port);
        let do_approve = yes || confirm(&prompt)?;
        if do_approve {
            let reason = format!("user-approved from run {uuid}");
            crate::ipc_client::insert_user_rule_request(sock, "allow", "exact", &b.host, &reason)?;
            approved += 1;
        } else {
            skipped += 1;
        }
    }
    println!("Approved {approved}; skipped {skipped}.");
    Ok(0)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockEntry {
    pub host: String,
    pub port: u16,
    pub source_kind: String,
}

pub fn filter_block_destinations(log_path: &Path, run_uuid: &str)
    -> Result<Vec<BlockEntry>, CliError>
{
    use std::io::{BufReader};
    let file = match std::fs::File::open(log_path) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Err(CliError::Other(format!("log file missing: {}", log_path.display())));
        }
        Err(e) => return Err(CliError::Other(format!("open log: {e}"))),
    };
    let reader = BufReader::new(file);
    let mut seen: std::collections::HashSet<(String, u16)> = std::collections::HashSet::new();
    let mut out = Vec::new();
    for line in reader.lines() {
        let line = match line { Ok(l) => l, Err(_) => continue };
        if line.trim().is_empty() { continue; }
        let v: serde_json::Value = match serde_json::from_str(&line) { Ok(v) => v, Err(_) => continue };
        if v.get("event").and_then(|e| e.as_str()) != Some("block") { continue; }
        if v.get("run_uuid").and_then(|r| r.as_str()) != Some(run_uuid) { continue; }
        let host = v.get("dest_host").and_then(|h| h.as_str()).unwrap_or("");
        let port = v.get("dest_port").and_then(|p| p.as_u64()).unwrap_or(0) as u16;
        let source_kind = v.get("source_kind").and_then(|s| s.as_str()).unwrap_or("").to_string();
        if host.is_empty() { continue; }
        if seen.insert((host.to_string(), port)) {
            out.push(BlockEntry { host: host.to_string(), port, source_kind });
        }
    }
    Ok(out)
}
