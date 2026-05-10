//! M004-S06: Integration test validating resilience & anti-tamper features.
//!
//! Covers:
//!   - HMAC key generation + round-trip (S02)
//!   - Hook self-check verify function (S03)
//!   - env_scrub hidden-key filtering (S04)
//!   - Manifest HMAC field present when key exists (S02)

use sentinel_core::Snapshot;
use sentinel_daemon::hmac_key;
use sentinel_daemon::manifest;
use sentinel_daemon::snapshot::publish_run;
use sentinel_daemon::state_dir::{ensure_runs_dir, ensure_state_dir, run_manifest_path};
use sentinel_hook::env_scrub;
use sentinel_hook::self_check;

#[test]
fn hmac_key_roundtrip_and_snapshot_signing() {
    let tmp = tempfile::tempdir().unwrap();
    let state_dir = tmp.path();
    ensure_state_dir(state_dir).unwrap();
    ensure_runs_dir(state_dir).unwrap();

    // Generate key
    let key = hmac_key::generate_and_store(state_dir).unwrap();
    assert_ne!(key, [0u8; 32], "key must not be all zeros");

    // Load key back
    let loaded = hmac_key::load(state_dir).unwrap();
    assert_eq!(key, loaded, "round-trip key must match");

    // Publish a snapshot (publish_run reads the key from state_dir)
    let snap = Snapshot::phase2_default();
    let uuid = "m004-integ-001";
    let pub_ = publish_run(state_dir, &snap, uuid).unwrap();

    // HMAC must be present in published result
    assert!(
        pub_.hmac_hex.is_some(),
        "publish_run must produce hmac when key present"
    );

    // HMAC must be in the manifest file
    let manifest_path = run_manifest_path(state_dir, uuid);
    let text = std::fs::read_to_string(&manifest_path).unwrap();
    let parsed = manifest::parse(&text).unwrap();
    assert!(
        parsed.hmac_hex.is_some(),
        "manifest must contain hmac= line"
    );
    assert_eq!(
        parsed.hmac_hex.unwrap(),
        pub_.hmac_hex.unwrap(),
        "manifest hmac must match published hmac"
    );
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
fn env_scrub_filters_sentinel_vars() {
    assert!(env_scrub::is_hidden_key(c"SENTINEL_SNAPSHOT_MANIFEST".as_ptr()));
    assert!(env_scrub::is_hidden_key(c"SENTINEL_DAEMON_SOCKET".as_ptr()));
    assert!(env_scrub::is_hidden_key(c"SENTINEL_STATE_DIR".as_ptr()));
    assert!(env_scrub::is_hidden_key(c"DYLD_INSERT_LIBRARIES".as_ptr()));
    assert!(!env_scrub::is_hidden_key(c"HOME".as_ptr()));
    assert!(!env_scrub::is_hidden_key(c"PATH".as_ptr()));
    assert!(!env_scrub::is_hidden_key(c"npm_config_registry".as_ptr()));
}

#[test]
fn hmac_no_key_means_no_hmac_in_manifest() {
    let tmp = tempfile::tempdir().unwrap();
    let state_dir = tmp.path();
    ensure_state_dir(state_dir).unwrap();
    ensure_runs_dir(state_dir).unwrap();

    // Publish WITHOUT generating a key
    let snap = Snapshot::phase2_default();
    let uuid = "m004-integ-nokey";
    let pub_ = publish_run(state_dir, &snap, uuid).unwrap();

    assert!(
        pub_.hmac_hex.is_none(),
        "publish_run without key should not produce hmac"
    );

    let manifest_path = run_manifest_path(state_dir, uuid);
    let text = std::fs::read_to_string(&manifest_path).unwrap();
    let parsed = manifest::parse(&text).unwrap();
    assert!(
        parsed.hmac_hex.is_none(),
        "manifest without key should not have hmac= line"
    );
}
