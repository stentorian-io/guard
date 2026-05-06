//! crates/sentinel-daemon/src/env_capture.rs
//!
//! Phase 3 plan 03-04 — PM env subset extraction (D-55).
//!
//! Strict allowlist by prefix + exact-match denylist for known-secret keys (R-08
//! mitigation per RESEARCH.md). Per-value truncation at 512 bytes; total wire-size
//! cap at sentinel_ipc::ExecEvent::MAX_PM_ENV_BYTES (4 KiB).

use sentinel_ipc::ExecEvent;

/// Per CONTEXT.md "Claude's Discretion > PM env-key allowlist contents (D-55)".
pub const PM_ENV_PREFIXES: &[&str] = &[
    "npm_",
    "PIP_",
    "VIRTUAL_ENV",
    "CARGO_",
    "BUNDLE_",
    "GEM_HOME",
    "GO",        // covers GOPATH, GOPROXY, GOMODCACHE, GOROOT, GOFLAGS
    "MIX_",
    "HEX_",
    "COMPOSER_",
];

/// Per RESEARCH.md "Open Questions for Planner Discretion §7" (R-08 mitigation).
/// Exact-match (case-sensitive) denylist for keys whose VALUES are credentials,
/// even though the KEYS happen to match a PM_ENV_PREFIXES entry.
pub const SECRET_DENYLIST: &[&str] = &[
    // npm authentication / publish credentials
    "npm_config_authToken",
    "npm_config_password",
    "npm_config_email",
    "npm_config__auth",
    // pip index URLs may contain inline credentials (https://user:pass@host)
    "PIP_INDEX_URL",
    "PIP_EXTRA_INDEX_URL",
    // bundler private gem index credentials
    "BUNDLE_GITHUB__COM",
    "BUNDLE_GEMS__CONTRIBSYS__COM",
    // cargo crates.io publish token
    "CARGO_REGISTRY_TOKEN",
    // composer auth file overrides
    "COMPOSER_AUTH",
];

const MAX_VALUE_BYTES: usize = 512;

/// Filter `env` to PM-relevant keys, dropping secrets and respecting the wire cap.
///
/// Algorithm:
/// 1. Skip any pair whose key is in SECRET_DENYLIST (exact-match, case-sensitive).
/// 2. Skip any pair whose key does NOT start with one of PM_ENV_PREFIXES.
/// 3. Truncate each surviving value to MAX_VALUE_BYTES (512) respecting UTF-8 char boundaries.
/// 4. Stop adding pairs once cumulative wire size (key.len() + value.len() + 2) would
///    exceed ExecEvent::MAX_PM_ENV_BYTES (4 KiB).
/// 5. Return captured pairs preserving input order.
pub fn extract_pm_env(env: &[(String, String)]) -> Vec<(String, String)> {
    let mut out: Vec<(String, String)> = Vec::new();
    let mut total = 0usize;
    for (k, v) in env {
        // R-08: explicit exact-match denylist takes precedence over prefix-allowlist.
        if SECRET_DENYLIST.iter().any(|d| *d == k.as_str()) {
            continue;
        }
        // Prefix-allowlist gate.
        if !PM_ENV_PREFIXES.iter().any(|p| k.starts_with(p)) {
            continue;
        }
        // Per-value truncation (defensive — a key passes prefix gate but holds a
        // surprise large value, e.g. malformed env data).
        let value = if v.len() > MAX_VALUE_BYTES {
            // Truncate respecting UTF-8 char boundaries.
            let mut end = MAX_VALUE_BYTES;
            while !v.is_char_boundary(end) && end > 0 {
                end -= 1;
            }
            v[..end].to_string()
        } else {
            v.clone()
        };
        // Wire-size cap (4 KiB total). 2-byte overhead per pair approximates
        // CBOR small-map framing (1-byte key-len + 1-byte val-len for short strings).
        let pair_size = k.len() + value.len() + 2;
        if total + pair_size > ExecEvent::MAX_PM_ENV_BYTES {
            break;
        }
        total += pair_size;
        out.push((k.clone(), value));
    }
    out
}
