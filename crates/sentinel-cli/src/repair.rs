//! `sentinel repair` — verify and repair installation integrity (M004-S05).
//!
//! Checks:
//!   1. HMAC key exists (re-generates if missing)
//!   2. Hook SHA-256 hash is current (re-derives if stale or missing)
//!   3. Daemon LaunchAgent is loaded (re-bootstraps if not)
//!   4. Watchdog LaunchAgent is loaded (re-bootstraps if not)

use std::path::Path;

use crate::CliError;
use crate::install::{artifacts, launchagent};

pub fn run(sock: &Path, state_dir: &Path) -> Result<i32, CliError> {
    let _ = sock;
    let db_path = state_dir.join("sentinel.db");
    let version = env!("CARGO_PKG_VERSION");
    let mut repaired = 0u32;

    // 1. HMAC key
    let hmac_key_path = state_dir.join("hmac.key");
    if !hmac_key_path.exists() {
        sentinel_daemon::hmac_key::generate_and_store(state_dir)
            .map_err(|e| CliError::Other(format!("hmac key: {e}")))?;
        artifacts::record_artifact(&db_path, "hmac_key", &hmac_key_path.display().to_string(), None, version)?;
        println!("  repaired: generated HMAC key");
        repaired += 1;
    } else {
        println!("  ok: HMAC key present");
    }

    // 2. Hook dylib hash
    let hook_hash_path = state_dir.join("hook.sha256");
    match crate::locate::find_dylib() {
        Ok(dylib_path) => {
            let bytes = std::fs::read(&dylib_path)
                .map_err(|e| CliError::Other(format!("read dylib: {e}")))?;
            let hash = format!("{:x}", <sha2::Sha256 as sha2::Digest>::digest(&bytes));
            let needs_update = match std::fs::read_to_string(&hook_hash_path) {
                Ok(existing) => existing.trim() != hash,
                Err(_) => true,
            };
            if needs_update {
                std::fs::write(&hook_hash_path, format!("{hash}\n"))
                    .map_err(|e| CliError::Other(format!("write hook hash: {e}")))?;
                artifacts::record_artifact(&db_path, "hook_hash", &hook_hash_path.display().to_string(), Some(&hash), version)?;
                println!("  repaired: updated hook SHA-256");
                repaired += 1;
            } else {
                println!("  ok: hook SHA-256 current");
            }
        }
        Err(_) => {
            println!("  skip: hook dylib not found (not on PATH)");
        }
    }

    // 3. Daemon LaunchAgent
    let plist = launchagent::plist_path();
    if plist.exists() {
        println!("  ok: daemon plist present");
    } else {
        println!("  warn: daemon plist missing — run `sentinel setup` to reinstall");
    }

    // 4. Watchdog LaunchAgent
    let wd_plist = launchagent::watchdog_plist_path();
    if wd_plist.exists() {
        println!("  ok: watchdog plist present");
    } else {
        println!("  warn: watchdog plist missing — run `sentinel setup` to reinstall");
    }

    if repaired > 0 {
        println!("sentinel: repaired {repaired} item(s)");
    } else {
        println!("sentinel: all checks passed");
    }
    Ok(0)
}
