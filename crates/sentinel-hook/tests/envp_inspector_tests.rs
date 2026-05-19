//! Tests for `sentinel_hook::envp::should_emit_env_not_propagated_gap`
//! (TREE-06 gap-closure 02-09).
//!
//! Test 4: should_emit_env_not_propagated_gap returns false when both required
//!   vars are present; true when either is missing; true on null envp.
//! Test 5: inspector handles arbitrarily-ordered envp; prefix anchoring avoids
//!   false matches on values that contain the key name as a substring.

use sentinel_hook::envp::should_emit_env_not_propagated_gap;
use std::ffi::CString;

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

#[cfg_attr(not(target_os = "macos"), ignore)]
#[test]
fn both_present_returns_false() {
    let entries = [
        "DYLD_INSERT_LIBRARIES=/some/path.dylib",
        "SENTINEL_SNAPSHOT_MANIFEST=/tmp/manifest.txt",
        "OTHER_VAR=value",
    ];
    let (_cstrings, ptrs) = make_envp(&entries);
    let result = unsafe { should_emit_env_not_propagated_gap(ptrs.as_ptr()) };
    assert!(
        !result,
        "should return false when both required env vars are present"
    );
}

#[cfg_attr(not(target_os = "macos"), ignore)]
#[test]
fn missing_dyld_insert_libraries_returns_true() {
    let entries = [
        "SENTINEL_SNAPSHOT_MANIFEST=/tmp/manifest.txt",
    ];
    let (_cstrings, ptrs) = make_envp(&entries);
    let result = unsafe { should_emit_env_not_propagated_gap(ptrs.as_ptr()) };
    assert!(
        result,
        "should return true when DYLD_INSERT_LIBRARIES is missing"
    );
}

#[cfg_attr(not(target_os = "macos"), ignore)]
#[test]
fn missing_sentinel_snapshot_manifest_returns_true() {
    let entries = [
        "DYLD_INSERT_LIBRARIES=/some/path.dylib",
    ];
    let (_cstrings, ptrs) = make_envp(&entries);
    let result = unsafe { should_emit_env_not_propagated_gap(ptrs.as_ptr()) };
    assert!(
        result,
        "should return true when SENTINEL_SNAPSHOT_MANIFEST is missing"
    );
}

#[cfg_attr(not(target_os = "macos"), ignore)]
#[test]
fn null_envp_returns_true() {
    // Null envp = no env vars at all → both are missing.
    let result = unsafe { should_emit_env_not_propagated_gap(std::ptr::null()) };
    assert!(result, "should return true when envp is null");
}

#[cfg_attr(not(target_os = "macos"), ignore)]
#[test]
fn empty_envp_returns_true() {
    // Empty envp: only the null terminator → both are missing.
    let ptrs: Vec<*mut libc::c_char> = vec![std::ptr::null_mut()];
    let result = unsafe { should_emit_env_not_propagated_gap(ptrs.as_ptr()) };
    assert!(result, "should return true when envp is empty (just null terminator)");
}

// ---- Test 5: order-independence and prefix anchoring ----

#[cfg_attr(not(target_os = "macos"), ignore)]
#[test]
fn order_independent_both_in_reverse_order() {
    // Keys present in reverse order — result must still be false.
    let entries = [
        "UNRELATED=something",
        "SENTINEL_SNAPSHOT_MANIFEST=/tmp/manifest.txt",
        "DYLD_INSERT_LIBRARIES=/some/path.dylib",
        "ANOTHER_VAR=42",
    ];
    let (_cstrings, ptrs) = make_envp(&entries);
    let result = unsafe { should_emit_env_not_propagated_gap(ptrs.as_ptr()) };
    assert!(
        !result,
        "order must not matter — both present → false"
    );
}

#[cfg_attr(not(target_os = "macos"), ignore)]
#[test]
fn prefix_anchoring_avoids_false_match_on_value_substring() {
    // A value that CONTAINS "DYLD_INSERT_LIBRARIES=" as a substring must NOT
    // be misidentified as the DYLD_INSERT_LIBRARIES key — the check must be
    // anchored at the start of the entry.
    let entries = [
        // This entry's VALUE contains "DYLD_INSERT_LIBRARIES=" but the KEY is "NOTE".
        "NOTE=DYLD_INSERT_LIBRARIES=should_not_match",
        "SENTINEL_SNAPSHOT_MANIFEST=/tmp/manifest.txt",
        // DYLD_INSERT_LIBRARIES is intentionally absent.
    ];
    let (_cstrings, ptrs) = make_envp(&entries);
    let result = unsafe { should_emit_env_not_propagated_gap(ptrs.as_ptr()) };
    assert!(
        result,
        "prefix anchoring must prevent false match: DYLD_INSERT_LIBRARIES absent → true"
    );
}

#[cfg_attr(not(target_os = "macos"), ignore)]
#[test]
fn prefix_anchoring_correct_match_at_start() {
    // Entries where all three keys appear at the start of their respective entries.
    let entries = [
        "DYLD_INSERT_LIBRARIES=actual_value",
        "SENTINEL_SNAPSHOT_MANIFEST=actual_manifest",
    ];
    let (_cstrings, ptrs) = make_envp(&entries);
    let result = unsafe { should_emit_env_not_propagated_gap(ptrs.as_ptr()) };
    assert!(
        !result,
        "both present at correct prefix positions → false"
    );
}
