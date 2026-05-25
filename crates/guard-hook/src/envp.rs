//! Pre-spawn envp inspector (TREE-06 — gap-closure 02-09).
//!
//! Pure-function helper called from `replace_fork.rs::guard_posix_spawn`
//! and `guard_posix_spawnp` to determine whether to emit an
//! `EnvNotPropagatedGap` before the real libc::posix_spawn fires.
//!
//! The check is prefix-anchored: each envp entry must START with the key
//! (e.g. the platform hook injection key) to match, preventing false positives
//! from values that contain the key name as a substring.

use core::ffi::c_char;

#[cfg(target_os = "macos")]
const HOOK_INJECTION_KEY: &[u8] = b"DYLD_INSERT_LIBRARIES=";
#[cfg(target_os = "linux")]
const HOOK_INJECTION_KEY: &[u8] = b"LD_PRELOAD=";
#[cfg(not(any(target_os = "macos", target_os = "linux")))]
const HOOK_INJECTION_KEY: &[u8] = b"LD_PRELOAD=";

const REQUIRED_KEYS: &[&[u8]] = &[HOOK_INJECTION_KEY, b"STT_GUARD_SNAPSHOT_MANIFEST="];

/// Walks the null-terminated envp array and returns true if ANY of the three
/// required Stentorian Guard env vars is missing. Returns true if envp is null (treat
/// as "no env vars at all").
///
/// # Safety
/// `envp` must either be null or point to a null-terminated array of either
/// null or NUL-terminated C-string pointers. MAX_ENVP_ENTRIES (4096) bounds
/// the walk against a malformed (non-null-terminated) envp.
pub unsafe fn should_emit_env_not_propagated_gap(envp: *const *mut c_char) -> bool {
    if envp.is_null() {
        return true;
    }
    let mut found = [false; 2];
    let mut i: isize = 0;
    // Cap the walk at 4096 entries to bound worst-case (defensive against a
    // malformed envp without a null terminator).
    const MAX_ENVP_ENTRIES: isize = 4096;
    while i < MAX_ENVP_ENTRIES {
        let p = unsafe { *envp.offset(i) };
        if p.is_null() {
            break;
        }
        for (k_idx, key) in REQUIRED_KEYS.iter().enumerate() {
            if bytes_eq_prefix(p, key) {
                found[k_idx] = true;
            }
        }
        if found.iter().all(|&x| x) {
            return false;
        }
        i += 1;
    }
    !found.iter().all(|&x| x)
}

/// Returns true if the C-string at `p` starts with `key` byte-for-byte.
/// Anchored at the start (avoids false matches on values that contain the
/// key name as substring text).
///
/// # Safety
/// `p` must be non-null and point to a NUL-terminated C string of at least
/// key.len() bytes. Callers ensure non-null before calling.
fn bytes_eq_prefix(p: *const c_char, key: &[u8]) -> bool {
    if p.is_null() {
        return false;
    }
    for (i, k_byte) in key.iter().enumerate() {
        // SAFETY: caller's invariant — p points to a NUL-terminated C string,
        // so we read byte-by-byte until we either hit a NUL or exhaust the key.
        let b = unsafe { *p.add(i) as u8 };
        if b == 0 {
            return false; // C-string ended before key did
        }
        if b != *k_byte {
            return false;
        }
    }
    true
}
