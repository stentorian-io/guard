//! crates/guard-cli/src/logs.rs
//!
//! `stt-guard status logs` — dump the JSONL forensic log to stdout.
//! For streaming Stentorian Guard logs, pipe to `tail -f ~/Library/Logs/Stentorian Guard/stt-guard.log`.

use std::io::Write;

use crate::CliError;
use crate::install::launchagent::logs_dir;

pub fn run_logs() -> Result<i32, CliError> {
    let active = logs_dir().join("stt-guard.log");
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
