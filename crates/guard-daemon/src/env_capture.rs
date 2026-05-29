//! crates/guard-daemon/src/env_capture.rs
//!
//! v0.3 — PM env subset extraction.
//!
//! Delegates filtering logic to `guard_core::env_filter` (single source of
//! truth). Per-value truncation at 512 bytes; total wire-size cap at
//! `guard_ipc::ExecEvent::MAX_PM_ENV_BYTES` (4 KiB).

use guard_core::env_filter;
use guard_ipc::ExecEvent;

#[must_use]
pub fn extract_pm_env(env: &[(String, String)]) -> Vec<(String, String)> {
    let mut out: Vec<(String, String)> = Vec::new();
    let mut total = 0usize;
    for (k, v) in env {
        if env_filter::is_secret_key(k.as_str()) {
            continue;
        }
        if !env_filter::is_pm_env_key(k) {
            continue;
        }
        let value = env_filter::truncate_value(v).to_string();
        let pair_size = k.len() + value.len() + 2;
        if total + pair_size > ExecEvent::MAX_PM_ENV_BYTES {
            break;
        }
        total += pair_size;
        out.push((k.clone(), value));
    }
    out
}
