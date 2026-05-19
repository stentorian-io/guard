//! crates/sentinel-cli/src/logs.rs
//!
//! `sentinel status logs` — dump the JSONL forensic log to stdout.
//! For streaming, pipe to `tail -f ~/Library/Logs/Sentinel/sentinel.log`.

use std::io::Write;

use crate::install::launchagent::logs_dir;
use crate::CliError;

pub fn run_logs() -> Result<i32, CliError> {
    let active = logs_dir().join("sentinel.log");
    run_dump(&active)
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
