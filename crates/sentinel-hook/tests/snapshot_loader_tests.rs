//! Constructor-time snapshot loader tests using a tempdir as a fake state_dir.
//!
//! These tests run with the test process's HOME pointed at the tempdir so the
//! `well_known_state_dir()` path validator accepts paths under the tempdir.

use sentinel_core::Snapshot;
use sentinel_daemon::manifest;
use sentinel_daemon::snapshot::publish;
use sentinel_daemon::state_dir::ensure_state_dir;
use sentinel_hook::snapshot::{load_from_env, LoadError};
use std::sync::Mutex;

/// Tests that mutate process env must be serialized.
static ENV_LOCK: Mutex<()> = Mutex::new(());

/// RAII guard: captures the prior values of HOME and SENTINEL_SNAPSHOT_MANIFEST
/// at construction; restores them on Drop — even on test-closure panic. ISS-13
/// remediation: the closure runs between construction and Drop, so any env
/// mutation it makes (e.g. setting SENTINEL_SNAPSHOT_MANIFEST inside the test
/// body) is reverted by Drop before the next test acquires ENV_LOCK.
struct EnvGuard<'a> {
    _lock: std::sync::MutexGuard<'a, ()>,
    prev_home: Option<std::ffi::OsString>,
    prev_man: Option<std::ffi::OsString>,
}

impl<'a> EnvGuard<'a> {
    fn new(lock: &'a Mutex<()>) -> Self {
        let g = lock.lock().unwrap();
        let prev_home = std::env::var_os("HOME");
        let prev_man = std::env::var_os("SENTINEL_SNAPSHOT_MANIFEST");
        Self {
            _lock: g,
            prev_home,
            prev_man,
        }
    }
}

impl<'a> Drop for EnvGuard<'a> {
    fn drop(&mut self) {
        // Edition 2024: every env mutation must be inside its own `unsafe { }`
        // block (ISS-01). Each restore is wrapped individually.
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
fn happy_path_loads_phase1_default_snapshot() {
    let _t = with_fake_home(|state_dir| {
        let snap = Snapshot::phase1_default();
        let pub_ = publish(state_dir, &snap, 0xCAFE_BABE).unwrap();
        manifest::write(state_dir, &pub_).unwrap();
        unsafe {
            std::env::set_var(
                "SENTINEL_SNAPSHOT_MANIFEST",
                sentinel_daemon::state_dir::manifest_path(state_dir),
            );
        }
        let loaded = load_from_env().expect("happy path");
        assert_eq!(loaded.schema_version, 1);
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
        let snap = Snapshot::phase1_default();
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
