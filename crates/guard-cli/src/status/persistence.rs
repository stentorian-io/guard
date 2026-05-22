//! `stt-guard status persistence [UUID]` — list detected persistence-write
//! events from the JSONL forensic log (M003-S05).

use crate::CliError;
use crate::install::launchagent;
use crate::persistence_log;

pub fn run(run_uuid: Option<&str>) -> Result<i32, CliError> {
    let log_path = launchagent::logs_dir().join(guard_core::paths::LOG_FILENAME);
    let entries = persistence_log::filter_persistence_writes(&log_path, run_uuid)?;

    if entries.is_empty() {
        match run_uuid {
            Some(uuid) => println!("No persistence-write events for run_uuid={uuid}."),
            None => println!("No persistence-write events recorded."),
        }
        return Ok(0);
    }
    println!("Persistence writes detected ({} total):", entries.len());
    for e in &entries {
        let pid_str = e.pid.map(|p| format!(" pid={p}")).unwrap_or_default();
        println!("  {} {} run={}{}", e.ts, e.binary_path, e.run_uuid, pid_str);
    }
    Ok(0)
}
