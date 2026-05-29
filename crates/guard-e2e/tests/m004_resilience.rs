//! M004-S06: Integration test validating resilience & anti-tamper features.
//!
//! Covers:
//!   - Hook self-check verify function (S03)
//!   - `env_scrub` hidden-key filtering (S04)

use guard_hook::env_scrub;
use guard_hook::self_check;

fn is_hidden_test_key(key: &'static std::ffi::CStr) -> bool {
    // SAFETY: C string literals are valid NUL-terminated strings.
    unsafe { env_scrub::is_hidden_key(key.as_ptr()) }
}

#[test]
fn self_check_passes_without_hash_file() {
    let tmp = tempfile::tempdir().unwrap();
    assert!(
        self_check::verify(tmp.path()).is_ok(),
        "self-check should pass when no hash file exists (graceful degradation)"
    );
}

#[test]
fn self_check_rejects_malformed_hash() {
    let tmp = tempfile::tempdir().unwrap();
    std::fs::write(tmp.path().join("hook.sha256"), "bad-hash\n").unwrap();
    assert!(
        self_check::verify(tmp.path()).is_err(),
        "self-check should reject malformed hash file"
    );
}

#[test]
fn env_scrub_filters_guard_vars() {
    assert!(is_hidden_test_key(c"STT_GUARD_SNAPSHOT_MANIFEST"));
    assert!(is_hidden_test_key(c"STT_GUARD_STATE_DIR"));
    assert!(is_hidden_test_key(c"DYLD_INSERT_LIBRARIES"));
    assert!(!is_hidden_test_key(c"HOME"));
    assert!(!is_hidden_test_key(c"PATH"));
    assert!(!is_hidden_test_key(c"npm_config_registry"));
}
