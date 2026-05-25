//! Tests for `guard_hook::envp::should_emit_env_not_propagated_gap`
//! (TREE-06 gap-closure 02-09).
//!
//! Test 4: should_emit_env_not_propagated_gap returns false when both required
//!   vars are present; true when either is missing; true on null envp.
//! Test 5: inspector handles arbitrarily-ordered envp; prefix anchoring avoids
//!   false matches on values that contain the key name as a substring.

use guard_hook::envp::should_emit_env_not_propagated_gap;
use std::ffi::CString;

#[cfg(target_os = "macos")]
const HOOK_ENV_ENTRY: &str = "DYLD_INSERT_LIBRARIES=/some/path.dylib";
#[cfg(target_os = "linux")]
const HOOK_ENV_ENTRY: &str = "LD_PRELOAD=/some/path.so";

#[cfg(target_os = "macos")]
const HOOK_ENV_PRESENT_ENTRY: &str = "DYLD_INSERT_LIBRARIES=actual_value";
#[cfg(target_os = "linux")]
const HOOK_ENV_PRESENT_ENTRY: &str = "LD_PRELOAD=actual_value";

#[cfg(target_os = "macos")]
const HOOK_ENV_KEY: &str = "DYLD_INSERT_LIBRARIES";
#[cfg(target_os = "linux")]
const HOOK_ENV_KEY: &str = "LD_PRELOAD";

/// Build a null-terminated envp array from a &[&str] of KEY=value entries.
/// Returns (the CStrings — must be kept alive, the *mut c_char array).
fn make_envp(entries: &[&str]) -> (Vec<CString>, Vec<*mut libc::c_char>) {
    let cstrings: Vec<CString> = entries
        .iter()
        .map(|s| CString::new(*s).expect("CString"))
        .collect();
    let mut ptrs: Vec<*mut libc::c_char> = cstrings
        .iter()
        .map(|cs| cs.as_ptr() as *mut libc::c_char)
        .collect();
    ptrs.push(std::ptr::null_mut()); // null terminator
    (cstrings, ptrs)
}

// ---- Test 4: presence / absence of the two required env vars ----

#[cfg(any(target_os = "macos", target_os = "linux"))]
#[test]
fn both_present_returns_false() {
    let entries = [
        HOOK_ENV_ENTRY,
        "STT_GUARD_SNAPSHOT_MANIFEST=/tmp/manifest.txt",
        "OTHER_VAR=value",
    ];
    let (_cstrings, ptrs) = make_envp(&entries);
    let result = unsafe { should_emit_env_not_propagated_gap(ptrs.as_ptr()) };
    assert!(
        !result,
        "should return false when both required env vars are present"
    );
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
#[test]
fn missing_hook_injection_env_returns_true() {
    let entries = ["STT_GUARD_SNAPSHOT_MANIFEST=/tmp/manifest.txt"];
    let (_cstrings, ptrs) = make_envp(&entries);
    let result = unsafe { should_emit_env_not_propagated_gap(ptrs.as_ptr()) };
    assert!(result, "should return true when {HOOK_ENV_KEY} is missing");
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
#[test]
fn missing_guard_snapshot_manifest_returns_true() {
    let entries = [HOOK_ENV_ENTRY];
    let (_cstrings, ptrs) = make_envp(&entries);
    let result = unsafe { should_emit_env_not_propagated_gap(ptrs.as_ptr()) };
    assert!(
        result,
        "should return true when STT_GUARD_SNAPSHOT_MANIFEST is missing"
    );
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
#[test]
fn null_envp_returns_true() {
    // Null envp = no env vars at all → both are missing.
    let result = unsafe { should_emit_env_not_propagated_gap(std::ptr::null()) };
    assert!(result, "should return true when envp is null");
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
#[test]
fn empty_envp_returns_true() {
    // Empty envp: only the null terminator → both are missing.
    let ptrs: Vec<*mut libc::c_char> = vec![std::ptr::null_mut()];
    let result = unsafe { should_emit_env_not_propagated_gap(ptrs.as_ptr()) };
    assert!(
        result,
        "should return true when envp is empty (just null terminator)"
    );
}

// ---- Test 5: order-independence and prefix anchoring ----

#[cfg(any(target_os = "macos", target_os = "linux"))]
#[test]
fn order_independent_both_in_reverse_order() {
    // Keys present in reverse order — result must still be false.
    let entries = [
        "UNRELATED=something",
        "STT_GUARD_SNAPSHOT_MANIFEST=/tmp/manifest.txt",
        HOOK_ENV_ENTRY,
        "ANOTHER_VAR=42",
    ];
    let (_cstrings, ptrs) = make_envp(&entries);
    let result = unsafe { should_emit_env_not_propagated_gap(ptrs.as_ptr()) };
    assert!(!result, "order must not matter — both present → false");
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
#[test]
fn prefix_anchoring_avoids_false_match_on_value_substring() {
    // A value that CONTAINS the hook-injection key as a substring must NOT
    // be misidentified as the hook-injection key — the check must be
    // anchored at the start of the entry.
    let note_entry = format!("NOTE={HOOK_ENV_KEY}=should_not_match");
    let entries = [
        note_entry.as_str(),
        "STT_GUARD_SNAPSHOT_MANIFEST=/tmp/manifest.txt",
        // The platform hook injection key is intentionally absent.
    ];
    let (_cstrings, ptrs) = make_envp(&entries);
    let result = unsafe { should_emit_env_not_propagated_gap(ptrs.as_ptr()) };
    assert!(
        result,
        "prefix anchoring must prevent false match: {HOOK_ENV_KEY} absent → true"
    );
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
#[test]
fn prefix_anchoring_correct_match_at_start() {
    // Entries where all three keys appear at the start of their respective entries.
    let entries = [
        HOOK_ENV_PRESENT_ENTRY,
        "STT_GUARD_SNAPSHOT_MANIFEST=actual_manifest",
    ];
    let (_cstrings, ptrs) = make_envp(&entries);
    let result = unsafe { should_emit_env_not_propagated_gap(ptrs.as_ptr()) };
    assert!(!result, "both present at correct prefix positions → false");
}
