//! Dylib-side PM env capture + filtering.
//!
//! Walks the null-terminated envp** array passed to exec/posix_spawn, applies
//! the centralized allowlist + secret denylist from `sentinel_core::env_filter`,
//! and returns a `Vec<(String, String)>` matching the `ExecEvent::pm_env` wire
//! shape.

use core::ffi::{c_char, CStr};
use sentinel_core::env_filter;

const MAX_PM_ENV_BYTES: usize = sentinel_ipc::ExecEvent::MAX_PM_ENV_BYTES;

const MAX_ENVP_ENTRIES: isize = 4096;

fn split_env_entry(entry: &str) -> Option<(&str, &str)> {
    let eq = entry.find('=')?;
    Some((&entry[..eq], &entry[eq + 1..]))
}

pub fn filter_one(key: &str, value: &str) -> Option<(String, String)> {
    if env_filter::is_secret_key(key) {
        return None;
    }
    if !env_filter::is_pm_env_key(key) {
        return None;
    }
    Some((key.to_string(), env_filter::truncate_value(value).to_string()))
}

/// Walk the null-terminated envp** passed to exec/posix_spawn, filter to
/// PM-relevant keys, drop secrets, and return the pairs in a shape that
/// `ExecEvent::pm_env` accepts directly.
///
/// Returns an empty Vec when envp is null or contains no admissible entries.
/// The wire-size cap (`MAX_PM_ENV_BYTES`) is enforced here so the daemon never
/// has to reject an over-size payload from a Sentinel-owned dylib.
///
/// # Safety
/// `envp` must either be null or point to a null-terminated array of pointers,
/// each pointer either null or pointing to a NUL-terminated C string. This is
/// the POSIX exec/posix_spawn contract — callers in `replace_exec.rs` and
/// `replace_fork.rs` receive the array directly from the user (execve, posix_spawn)
/// or from the inherited `**environ` symbol.
pub unsafe fn extract_pm_env_from_envp(envp: *const *const c_char) -> Vec<(String, String)> {
    let mut out: Vec<(String, String)> = Vec::new();
    if envp.is_null() {
        return out;
    }
    let mut total = 0usize;
    let mut i: isize = 0;
    while i < MAX_ENVP_ENTRIES {
        // SAFETY: caller's invariant — envp is a null-terminated array of C-string pointers.
        let p = unsafe { *envp.offset(i) };
        if p.is_null() {
            break;
        }
        // SAFETY: caller's invariant — each non-null pointer is a NUL-terminated C string.
        let entry_cstr = unsafe { CStr::from_ptr(p) };
        // Use to_string_lossy so non-UTF-8 bytes do not panic; the resulting
        // String is a best-effort representation. Filtering is by key only,
        // so a mangled value byte cannot bypass the secret-key gate.
        let entry = entry_cstr.to_string_lossy();
        if let Some((key, value)) = split_env_entry(entry.as_ref()) {
            if let Some((k, v)) = filter_one(key, value) {
                // 2-byte CBOR-framing approximation per pair (matches daemon-side
                // accounting in env_capture::extract_pm_env).
                let pair_size = k.len() + v.len() + 2;
                if total + pair_size > MAX_PM_ENV_BYTES {
                    break;
                }
                total += pair_size;
                out.push((k, v));
            }
        }
        i += 1;
    }
    out
}

/// Convenience wrapper for posix_spawn shadows whose envp is `*const *mut c_char`
/// instead of `*const *const c_char`. Same contract / semantics.
///
/// # Safety
/// Same as `extract_pm_env_from_envp` — null OR null-terminated array of
/// (null OR NUL-terminated C-string) pointers.
pub unsafe fn extract_pm_env_from_envp_mut(
    envp: *const *mut c_char,
) -> Vec<(String, String)> {
    // Reinterpret as *const *const c_char — the writability of the inner
    // pointer is irrelevant for the read-only walk we perform.
    unsafe { extract_pm_env_from_envp(envp as *const *const c_char) }
}

/// Walk the inherited `**environ` symbol. Used by exec*p / execv / fork+exec
/// paths where the caller does not pass envp explicitly — the new image
/// inherits the parent's environment.
///
/// # Safety
/// Calls `libc::__environ` (extern "C" static `**environ`). Safe to read in
/// the dylib context: the global is set up by dyld before any user code,
/// and POSIX guarantees it is null-terminated. We treat a null pointer as
/// "no env" (returns empty Vec).
pub fn extract_pm_env_from_environ() -> Vec<(String, String)> {
    unsafe extern "C" {
        // Apple's libc exposes `environ` (not `__environ`) as the canonical
        // symbol. It is `*mut *mut c_char` — pointer to null-terminated array
        // of NUL-terminated C-string pointers.
        static environ: *const *const c_char;
    }
    // SAFETY: `environ` is a libc-managed global that is null-terminated by
    // POSIX contract; reading it is always safe in a dyld-loaded dylib (set
    // up before any user code runs). The walk itself is bounded by
    // MAX_ENVP_ENTRIES inside extract_pm_env_from_envp.
    unsafe { extract_pm_env_from_envp(environ) }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CString;

    /// Build a heap-allocated envp** for tests. Returns the envp pointer
    /// alongside the owning Vecs (so the caller drops them after the call).
    fn make_envp(entries: &[&str]) -> (Vec<CString>, Vec<*const c_char>) {
        let cstrings: Vec<CString> = entries
            .iter()
            .map(|s| CString::new(*s).unwrap())
            .collect();
        let mut ptrs: Vec<*const c_char> =
            cstrings.iter().map(|cs| cs.as_ptr()).collect();
        ptrs.push(std::ptr::null()); // null terminator
        (cstrings, ptrs)
    }

    #[test]
    fn null_envp_returns_empty() {
        let out = unsafe { extract_pm_env_from_envp(std::ptr::null()) };
        assert!(out.is_empty());
    }

    #[test]
    fn empty_envp_returns_empty() {
        let entries: &[&str] = &[];
        let (_owners, ptrs) = make_envp(entries);
        let out = unsafe { extract_pm_env_from_envp(ptrs.as_ptr()) };
        assert!(out.is_empty());
    }

    #[test]
    fn admits_npm_package_name() {
        let (_owners, ptrs) = make_envp(&[
            "PATH=/usr/bin",
            "npm_package_name=lodash",
            "HOME=/tmp",
        ]);
        let out = unsafe { extract_pm_env_from_envp(ptrs.as_ptr()) };
        assert_eq!(out.len(), 1, "got: {:?}", out);
        assert_eq!(out[0], ("npm_package_name".into(), "lodash".into()));
    }

    #[test]
    fn drops_npm_config_authtoken_secret_key() {
        // Exact-denylist entry — must be dropped even though it starts with `npm_`.
        let (_owners, ptrs) = make_envp(&[
            "npm_package_name=lodash",
            "npm_config_authToken=DECOY_LEAK_xyz",
        ]);
        let out = unsafe { extract_pm_env_from_envp(ptrs.as_ptr()) };
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].0, "npm_package_name");
        assert!(out.iter().all(|(_, v)| !v.contains("DECOY_LEAK_xyz")));
    }

    #[test]
    fn drops_substring_token_pattern() {
        let (_owners, ptrs) = make_envp(&[
            "CARGO_PKG_NAME=sentinel",
            "CARGO_REGISTRY_TOKEN=DECOY_TOKEN_abc",
            "npm_some_TOKEN_field=DECOY_npm_token_def",
        ]);
        let out = unsafe { extract_pm_env_from_envp(ptrs.as_ptr()) };
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].0, "CARGO_PKG_NAME");
        assert!(out.iter().all(|(_, v)| !v.contains("DECOY_TOKEN_abc")));
        assert!(out.iter().all(|(_, v)| !v.contains("DECOY_npm_token_def")));
    }

    #[test]
    fn drops_password_substring() {
        let (_owners, ptrs) = make_envp(&[
            "npm_package_name=lodash",
            "npm_password_setting=DECOY_PASS",
        ]);
        let out = unsafe { extract_pm_env_from_envp(ptrs.as_ptr()) };
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].0, "npm_package_name");
        assert!(out.iter().all(|(_, v)| !v.contains("DECOY_PASS")));
    }

    #[test]
    fn drops_auth_suffix() {
        let (_owners, ptrs) = make_envp(&[
            "npm_package_version=1.0.0",
            "npm_config__auth=DECOY_AUTH_xyz",
        ]);
        let out = unsafe { extract_pm_env_from_envp(ptrs.as_ptr()) };
        assert_eq!(out.len(), 1);
        assert!(out.iter().all(|(_, v)| !v.contains("DECOY_AUTH_xyz")));
    }

    #[test]
    fn drops_unprefixed_keys() {
        let (_owners, ptrs) = make_envp(&[
            "PATH=/usr/bin",
            "HOME=/tmp",
            "RANDOM_USER_VAR=value",
        ]);
        let out = unsafe { extract_pm_env_from_envp(ptrs.as_ptr()) };
        assert!(out.is_empty(), "got: {:?}", out);
    }

    #[test]
    fn truncates_oversized_value() {
        let big_value = "X".repeat(1024);
        let pair = format!("npm_package_long={big_value}");
        let (_owners, ptrs) = make_envp(&[&pair]);
        let out = unsafe { extract_pm_env_from_envp(ptrs.as_ptr()) };
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].1.len(), env_filter::MAX_VALUE_BYTES);
    }

    #[test]
    fn enforces_total_payload_cap() {
        // Build many `npm_*` entries, each 100 bytes (key) + 100 bytes (value),
        // so the cap kicks in well before all entries are admitted.
        let big_val = "Y".repeat(100);
        let mut entries: Vec<String> = Vec::new();
        for i in 0..50 {
            entries.push(format!("npm_test_long_key_{i:04}={big_val}"));
        }
        let entry_refs: Vec<&str> = entries.iter().map(|s| s.as_str()).collect();
        let (_owners, ptrs) = make_envp(&entry_refs);
        let out = unsafe { extract_pm_env_from_envp(ptrs.as_ptr()) };
        let total: usize = out.iter().map(|(k, v)| k.len() + v.len() + 2).sum();
        assert!(
            total <= MAX_PM_ENV_BYTES,
            "filter must enforce wire-size cap; got total={total}"
        );
    }

    #[test]
    fn case_insensitive_denylist_match() {
        // npm normalizes config-key env vars case-insensitively. Match should
        // catch `NPM_CONFIG_AUTHTOKEN` even though the literal denylist entry
        // is `npm_config_authToken`.
        let (_owners, ptrs) = make_envp(&[
            "NPM_CONFIG_AUTHTOKEN=DECOY_UPPER_TOKEN",
            "npm_package_name=lodash",
        ]);
        let out = unsafe { extract_pm_env_from_envp(ptrs.as_ptr()) };
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].0, "npm_package_name");
        assert!(out.iter().all(|(_, v)| !v.contains("DECOY_UPPER_TOKEN")));
    }

    #[test]
    fn malformed_entry_without_equals_dropped() {
        let (_owners, ptrs) = make_envp(&["npm_no_equals_sign", "npm_package_name=ok"]);
        let out = unsafe { extract_pm_env_from_envp(ptrs.as_ptr()) };
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].0, "npm_package_name");
    }

    #[test]
    fn empty_value_admitted() {
        let (_owners, ptrs) = make_envp(&["npm_package_name="]);
        let out = unsafe { extract_pm_env_from_envp(ptrs.as_ptr()) };
        assert_eq!(out.len(), 1);
        assert_eq!(out[0], ("npm_package_name".into(), String::new()));
    }

    #[test]
    fn cargo_pkg_name_admitted() {
        let (_owners, ptrs) = make_envp(&["CARGO_PKG_NAME=sentinel-hook"]);
        let out = unsafe { extract_pm_env_from_envp(ptrs.as_ptr()) };
        assert_eq!(out.len(), 1);
        assert_eq!(out[0], ("CARGO_PKG_NAME".into(), "sentinel-hook".into()));
    }

    #[test]
    fn pip_index_url_dropped_even_though_pip_prefixed() {
        // PIP_INDEX_URL is on the denylist (may contain inline credentials).
        let (_owners, ptrs) = make_envp(&[
            "PIP_INDEX_URL=https://user:pass@example.com/simple",
            "PIP_NO_CACHE_DIR=1",
        ]);
        let out = unsafe { extract_pm_env_from_envp(ptrs.as_ptr()) };
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].0, "PIP_NO_CACHE_DIR");
    }

    #[test]
    fn preserves_input_order() {
        let (_owners, ptrs) = make_envp(&[
            "npm_package_name=a",
            "CARGO_PKG_NAME=b",
            "npm_lifecycle_event=preinstall",
        ]);
        let out = unsafe { extract_pm_env_from_envp(ptrs.as_ptr()) };
        assert_eq!(out.len(), 3);
        assert_eq!(out[0].0, "npm_package_name");
        assert_eq!(out[1].0, "CARGO_PKG_NAME");
        assert_eq!(out[2].0, "npm_lifecycle_event");
    }
}
