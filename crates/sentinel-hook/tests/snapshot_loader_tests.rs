//! Constructor-time snapshot loader tests using a tempdir as a fake state_dir.
//!
//! These tests run with the test process's HOME pointed at the tempdir so the
//! `well_known_state_dir()` path validator accepts paths under the tempdir.

use sentinel_core::Snapshot;
use sentinel_daemon::hmac_key;
use sentinel_daemon::manifest;
use sentinel_daemon::snapshot::publish;
use sentinel_daemon::state_dir::ensure_state_dir;
use sentinel_hook::snapshot::{load_from_env, LoadError};
use std::sync::Mutex;

/// Tests that mutate process env must be serialized.
static ENV_LOCK: Mutex<()> = Mutex::new(());

/// RAII guard: captures the prior values of HOME, SENTINEL_SNAPSHOT_MANIFEST,
/// and SENTINEL_STATE_DIR at construction; restores them on Drop — even on
/// test-closure panic.
struct EnvGuard<'a> {
    _lock: std::sync::MutexGuard<'a, ()>,
    prev_home: Option<std::ffi::OsString>,
    prev_man: Option<std::ffi::OsString>,
    prev_state_dir: Option<std::ffi::OsString>,
}

impl<'a> EnvGuard<'a> {
    fn new(lock: &'a Mutex<()>) -> Self {
        let g = lock.lock().unwrap();
        let prev_home = std::env::var_os("HOME");
        let prev_man = std::env::var_os("SENTINEL_SNAPSHOT_MANIFEST");
        let prev_state_dir = std::env::var_os("SENTINEL_STATE_DIR");
        Self {
            _lock: g,
            prev_home,
            prev_man,
            prev_state_dir,
        }
    }
}

impl<'a> Drop for EnvGuard<'a> {
    fn drop(&mut self) {
        unsafe {
            match self.prev_home.take() {
                Some(v) => std::env::set_var("HOME", v),
                None => std::env::remove_var("HOME"),
            }
        }
        unsafe {
            match self.prev_man.take() {
                Some(v) => std::env::set_var("SENTINEL_SNAPSHOT_MANIFEST", v),
                None => std::env::remove_var("SENTINEL_SNAPSHOT_MANIFEST"),
            }
        }
        unsafe {
            match self.prev_state_dir.take() {
                Some(v) => std::env::set_var("SENTINEL_STATE_DIR", v),
                None => std::env::remove_var("SENTINEL_STATE_DIR"),
            }
        }
    }
}

fn with_fake_home<F: FnOnce(&std::path::Path)>(f: F) -> tempfile::TempDir {
    let tmp = tempfile::tempdir().unwrap();
    let home = tmp.path().to_path_buf();
    let state_dir = home.join("Library/Application Support/Sentinel");
    ensure_state_dir(&state_dir).unwrap();
    let _guard = EnvGuard::new(&ENV_LOCK);
    unsafe {
        std::env::set_var("HOME", &home);
    }
    f(&state_dir);
    // _guard's Drop runs on closure return (or panic) and restores HOME +
    // SENTINEL_SNAPSHOT_MANIFEST to their pre-test values, even if the test
    // closure mutated SENTINEL_SNAPSHOT_MANIFEST internally.
    tmp
}

#[test]
fn happy_path_loads_v2_default_snapshot() {
    let _t = with_fake_home(|state_dir| {
        // Migration: was v1_default. Snapshot::decode now rejects
        // SCHEMA_V1 (v0.2 made decode fail-closed); v2_default produces
        // a SCHEMA_V2 snapshot with non-empty entries (loopback v4/v6 + npmjs).
        let snap = Snapshot::v2_default();
        let pub_ = publish(state_dir, &snap, 0xCAFE_BABE).unwrap();
        manifest::write(state_dir, &pub_).unwrap();
        unsafe {
            std::env::set_var(
                "SENTINEL_SNAPSHOT_MANIFEST",
                sentinel_daemon::state_dir::manifest_path(state_dir),
            );
        }
        let loaded = load_from_env().expect("happy path");
        assert_eq!(loaded.schema_version, 2);
        assert!(!loaded.entries.is_empty());
    });
}

#[test]
fn fail_closed_when_env_unset() {
    let _t = with_fake_home(|_| {
        unsafe {
            std::env::remove_var("SENTINEL_SNAPSHOT_MANIFEST");
        }
        let r = load_from_env();
        assert!(matches!(r, Err(LoadError::EnvUnset)));
    });
}

#[test]
fn fail_closed_when_manifest_path_outside_state_dir() {
    let _t = with_fake_home(|_state_dir| {
        // Point the env var at a manifest in /tmp (definitely outside state_dir).
        let outside = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(outside.path(), "/etc/passwd\ndigest=00").unwrap();
        unsafe {
            std::env::set_var("SENTINEL_SNAPSHOT_MANIFEST", outside.path());
        }
        let r = load_from_env();
        match r {
            Err(LoadError::PathOutsideStateDir { .. }) => {}
            other => panic!("expected PathOutsideStateDir, got {:?}", other),
        }
    });
}

#[test]
fn fail_closed_on_digest_mismatch() {
    let _t = with_fake_home(|state_dir| {
        // Migration: was v1_default. SCHEMA_V2 fixture so the
        // decoder doesn't short-circuit before reaching the digest check.
        let snap = Snapshot::v2_default();
        let pub_ = publish(state_dir, &snap, 1).unwrap();
        // Tamper with the snapshot file AFTER manifest is written → digest mismatch.
        manifest::write(state_dir, &pub_).unwrap();
        let mut tamper = std::fs::read(&pub_.path).unwrap();
        tamper.push(0xFF);
        std::fs::write(&pub_.path, &tamper).unwrap();
        unsafe {
            std::env::set_var(
                "SENTINEL_SNAPSHOT_MANIFEST",
                sentinel_daemon::state_dir::manifest_path(state_dir),
            );
        }
        let r = load_from_env();
        assert!(matches!(r, Err(LoadError::DigestMismatch { .. })));
    });
}

// --- M004-S02 HMAC integrity tests ---

#[test]
fn hmac_happy_path_with_signed_manifest() {
    use sentinel_daemon::snapshot::publish_run;
    use sentinel_daemon::state_dir::ensure_runs_dir;

    let _t = with_fake_home(|state_dir| {
        ensure_runs_dir(state_dir).unwrap();
        hmac_key::generate_and_store(state_dir).unwrap();

        let snap = Snapshot::v2_default();
        let uuid = "hmac-test-0001";
        let pub_ = publish_run(state_dir, &snap, uuid).expect("publish_run");
        assert!(pub_.hmac_hex.is_some(), "publish_run must produce hmac when key present");

        let manifest_path = sentinel_daemon::state_dir::run_manifest_path(state_dir, uuid);
        unsafe {
            std::env::set_var("SENTINEL_SNAPSHOT_MANIFEST", &manifest_path);
            std::env::set_var("SENTINEL_STATE_DIR", state_dir);
        }
        let loaded = load_from_env().expect("HMAC happy path");
        assert_eq!(loaded.schema_version, 2);
        assert!(!loaded.entries.is_empty());
    });
}

#[test]
fn hmac_fail_closed_on_tampered_hmac() {
    use sentinel_daemon::snapshot::publish_run;
    use sentinel_daemon::state_dir::ensure_runs_dir;

    let _t = with_fake_home(|state_dir| {
        ensure_runs_dir(state_dir).unwrap();
        hmac_key::generate_and_store(state_dir).unwrap();

        let snap = Snapshot::v2_default();
        let uuid = "hmac-test-0002";
        let _pub = publish_run(state_dir, &snap, uuid).expect("publish_run");

        // Tamper with HMAC in the manifest
        let manifest_path = sentinel_daemon::state_dir::run_manifest_path(state_dir, uuid);
        let text = std::fs::read_to_string(&manifest_path).unwrap();
        let tampered = text.replace("hmac=", "hmac=0000000000000000000000000000000000000000000000000000000000000000\nold_hmac=");
        std::fs::write(&manifest_path, &tampered).unwrap();

        unsafe {
            std::env::set_var("SENTINEL_SNAPSHOT_MANIFEST", &manifest_path);
            std::env::set_var("SENTINEL_STATE_DIR", state_dir);
        }
        let r = load_from_env();
        assert!(matches!(r, Err(LoadError::HmacMismatch)), "expected HmacMismatch, got: {r:?}");
    });
}

#[test]
fn hmac_fail_closed_when_key_exists_but_manifest_has_no_hmac() {
    let _t = with_fake_home(|state_dir| {
        hmac_key::generate_and_store(state_dir).unwrap();

        // Publish WITHOUT key (simulate old-format manifest)
        let snap = Snapshot::v2_default();
        let pub_ = publish(state_dir, &snap, 0xDEAD).unwrap();
        // Write legacy manifest (no hmac line)
        manifest::write(state_dir, &pub_).unwrap();

        unsafe {
            std::env::set_var(
                "SENTINEL_SNAPSHOT_MANIFEST",
                sentinel_daemon::state_dir::manifest_path(state_dir),
            );
            std::env::set_var("SENTINEL_STATE_DIR", state_dir);
        }
        let r = load_from_env();
        assert!(matches!(r, Err(LoadError::HmacMissing)), "expected HmacMissing, got: {r:?}");
    });
}

#[test]
fn no_hmac_key_skips_verification() {
    let _t = with_fake_home(|state_dir| {
        // No key generated — legacy mode, HMAC check should be skipped
        let snap = Snapshot::v2_default();
        let pub_ = publish(state_dir, &snap, 0xBEEF).unwrap();
        manifest::write(state_dir, &pub_).unwrap();

        unsafe {
            std::env::set_var(
                "SENTINEL_SNAPSHOT_MANIFEST",
                sentinel_daemon::state_dir::manifest_path(state_dir),
            );
            std::env::set_var("SENTINEL_STATE_DIR", state_dir);
        }
        let loaded = load_from_env().expect("no-key should skip HMAC check");
        assert_eq!(loaded.schema_version, 2);
    });
}
