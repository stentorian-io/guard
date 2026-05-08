//! crates/sentinel-cli/src/logs.rs
//!
//! Phase 3 plan 03-10 — `sentinel logs [--follow]` (CLI-03, D-49..D-52).

use std::io::Write;

use crate::install::launchagent::logs_dir;
use crate::CliError;

/// `json`: future-facing flag; the JSONL forensic log is already JSON
/// natively, so for now this flag is a no-op (kept for D-23 parity with
/// other status reads — re-investigate if a different formatter is added).
pub fn run_logs(follow: bool, _json: bool) -> Result<i32, CliError> {
    let active = logs_dir().join("sentinel.log");
    if follow {
        crate::logs_follow::tail(&active).map(|()| 0)
    } else {
        run_dump(&active)
    }
}

fn run_dump(active: &std::path::Path) -> Result<i32, CliError> {
    let mut file = match std::fs::File::open(active) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(0), // silent on no log
        Err(e) => return Err(CliError::Other(format!("open log: {e}"))),
    };
    let stdout = std::io::stdout();
    let mut out = stdout.lock();
    let _ = std::io::copy(&mut file, &mut out);
    let _ = out.flush();
    Ok(0)
}
