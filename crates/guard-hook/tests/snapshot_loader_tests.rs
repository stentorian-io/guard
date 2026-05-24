//! Constructor-time snapshot loader tests using a tempdir as a fake state_dir.
//!
//! These tests run with the test process's HOME pointed at the tempdir so the
//! `well_known_state_dir()` path validator accepts paths under the tempdir.

use guard_core::Snapshot;
use guard_daemon::hmac_key;
use guard_daemon::snapshot::publish_run_signed_bytes;
use guard_daemon::state_dir::ensure_state_dir;
use guard_hook::snapshot::{load_from_env, LoadError};
use std::sync::Mutex;

/// Tests that mutate process env must be serialized.
static ENV_LOCK: Mutex<()> = Mutex::new(());

/// RAII guard: captures the prior values of HOME, STT_GUARD_SNAPSHOT_MANIFEST,
/// and STT_GUARD_STATE_DIR at construction; restores them on Drop — even on
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
        let prev_man = std::env::var_os("STT_GUARD_SNAPSHOT_MANIFEST");
        let prev_state_dir = std::env::var_os("STT_GUARD_STATE_DIR");
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
                Some(v) => std::env::set_var("STT_GUARD_SNAPSHOT_MANIFEST", v),
                None => std::env::remove_var("STT_GUARD_SNAPSHOT_MANIFEST"),
            }
        }
        unsafe {
            match self.prev_state_dir.take() {
                Some(v) => std::env::set_var("STT_GUARD_STATE_DIR", v),
                None => std::env::remove_var("STT_GUARD_STATE_DIR"),
            }
        }
    }
}

fn with_fake_home<F: FnOnce(&std::path::Path)>(f: F) -> tempfile::TempDir {
    let tmp = tempfile::tempdir().unwrap();
    let home = tmp.path().to_path_buf();
    let state_dir = home.join("Library/Application Support/Stentorian Guard");
    ensure_state_dir(&state_dir).unwrap();
    let _guard = EnvGuard::new(&ENV_LOCK);
    unsafe {
        std::env::set_var("HOME", &home);
    }
    f(&state_dir);
    // _guard's Drop runs on closure return (or panic) and restores HOME +
    // STT_GUARD_SNAPSHOT_MANIFEST to their pre-test values, even if the test
    // closure mutated STT_GUARD_SNAPSHOT_MANIFEST internally.
    tmp
}

fn signed_snapshot(
    mut snap: Snapshot,
    run_uuid: &str,
) -> (Vec<u8>, guard_core::SnapshotSignatureV1) {
    snap.run_uuid = Some(run_uuid.to_string());
    if snap.generated_at_unix_ms == 0 {
        snap.generated_at_unix_ms = 1_700_000_000_000;
    }
    let bytes = snap.encode().unwrap();
    let payload = guard_core::SnapshotSignaturePayloadV1::new(
        run_uuid,
        guard_core::sha256_hex(&bytes),
        snap.generated_at_unix_ms,
    );
    let signing_key = p256::ecdsa::SigningKey::from_slice(&[7u8; 32]).unwrap();
    let payload_bytes = guard_core::canonical_snapshot_payload_bytes(&payload).unwrap();
    let signature_der = {
        use p256::ecdsa::signature::Signer;
        let signature: p256::ecdsa::Signature = signing_key.sign(&payload_bytes);
        signature.to_der().as_bytes().to_vec()
    };
    let public_key_x963 = signing_key
        .verifying_key()
        .to_encoded_point(false)
        .as_bytes()
        .to_vec();
    let signature = guard_core::SnapshotSignatureV1 {
        scheme: guard_core::RULE_SIGNATURE_SCHEME_ECDSA_P256_SHA256.to_string(),
        signer_kind: guard_core::SIGNER_KIND_SECURE_ENCLAVE.to_string(),
        public_key_sha256: guard_core::sha256_hex(&public_key_x963),
        public_key_x963,
        signature_der,
        signed_payload_sha256: guard_core::sha256_hex(&payload_bytes),
        signature_created_at_unix_ms: snap.generated_at_unix_ms,
    };
    (bytes, signature)
}

fn write_trusted_signer(state_dir: &std::path::Path, signature: &guard_core::SnapshotSignatureV1) {
    std::fs::write(
        state_dir.join(guard_core::paths::TRUSTED_RULE_SIGNERS_FILENAME),
        format!(
            "{}\t{}\t{}\ttest\n",
            signature.public_key_sha256,
            signature.signer_kind,
            hex_lower(&signature.public_key_x963)
        ),
    )
    .unwrap();
}

fn publish_signed_run(
    state_dir: &std::path::Path,
    snap: Snapshot,
    run_uuid: &str,
) -> guard_daemon::snapshot::PublishedSnapshot {
    let (bytes, signature) = signed_snapshot(snap, run_uuid);
    write_trusted_signer(state_dir, &signature);
    publish_run_signed_bytes(state_dir, &bytes, run_uuid, &signature).expect("publish signed run")
}

fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 0x0f) as usize] as char);
    }
    s
}

#[test]
fn happy_path_loads_v2_default_snapshot() {
    let _t = with_fake_home(|state_dir| {
        // Migration: was v1_default. Snapshot::decode now rejects
        // SCHEMA_V1 (v0.2 made decode fail-closed); v2_default produces
        // a SCHEMA_V2 snapshot with non-empty entries (loopback v4/v6 + npmjs).
        let snap = Snapshot::v2_default();
        let uuid = "signed-test-0000";
        let _pub = publish_signed_run(state_dir, snap, uuid);
        unsafe {
            std::env::set_var(
                "STT_GUARD_SNAPSHOT_MANIFEST",
                guard_daemon::state_dir::run_manifest_path(state_dir, uuid),
            );
            std::env::set_var("STT_GUARD_STATE_DIR", state_dir);
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
            std::env::remove_var("STT_GUARD_SNAPSHOT_MANIFEST");
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
            std::env::set_var("STT_GUARD_SNAPSHOT_MANIFEST", outside.path());
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
        let uuid = "signed-test-0001";
        let pub_ = publish_signed_run(state_dir, snap, uuid);
        let mut tamper = std::fs::read(&pub_.path).unwrap();
        tamper.push(0xFF);
        std::fs::write(&pub_.path, &tamper).unwrap();
        unsafe {
            std::env::set_var(
                "STT_GUARD_SNAPSHOT_MANIFEST",
                guard_daemon::state_dir::run_manifest_path(state_dir, uuid),
            );
            std::env::set_var("STT_GUARD_STATE_DIR", state_dir);
        }
        let r = load_from_env();
        assert!(matches!(r, Err(LoadError::DigestMismatch { .. })));
    });
}

#[test]
fn fail_closed_when_snapshot_signature_missing() {
    let _t = with_fake_home(|state_dir| {
        let uuid = "sig-test-missing";
        let _pub = publish_signed_run(state_dir, Snapshot::v2_default(), uuid);
        let manifest_path = guard_daemon::state_dir::run_manifest_path(state_dir, uuid);
        let text = std::fs::read_to_string(&manifest_path).unwrap();
        let without_signature = text
            .lines()
            .filter(|line| !line.starts_with("snapshot_"))
            .collect::<Vec<_>>()
            .join("\n")
            + "\n";
        std::fs::write(&manifest_path, without_signature).unwrap();
        unsafe {
            std::env::set_var("STT_GUARD_SNAPSHOT_MANIFEST", &manifest_path);
            std::env::set_var("STT_GUARD_STATE_DIR", state_dir);
        }
        let r = load_from_env();
        assert!(
            matches!(r, Err(LoadError::SnapshotSignatureMissing)),
            "expected SnapshotSignatureMissing, got {r:?}"
        );
    });
}

#[test]
fn fail_closed_when_snapshot_signature_tampered() {
    let _t = with_fake_home(|state_dir| {
        let uuid = "sig-test-tampered";
        let _pub = publish_signed_run(state_dir, Snapshot::v2_default(), uuid);
        let manifest_path = guard_daemon::state_dir::run_manifest_path(state_dir, uuid);
        let text = std::fs::read_to_string(&manifest_path).unwrap();
        let tampered = text.replace("snapshot_signature_der=", "snapshot_signature_der=00");
        std::fs::write(&manifest_path, tampered).unwrap();
        unsafe {
            std::env::set_var("STT_GUARD_SNAPSHOT_MANIFEST", &manifest_path);
            std::env::set_var("STT_GUARD_STATE_DIR", state_dir);
        }
        let r = load_from_env();
        assert!(
            matches!(r, Err(LoadError::SnapshotSignatureMismatch(_))),
            "expected SnapshotSignatureMismatch, got {r:?}"
        );
    });
}

#[test]
fn fail_closed_when_snapshot_signer_untrusted() {
    let _t = with_fake_home(|state_dir| {
        let uuid = "sig-test-untrusted";
        let _pub = publish_signed_run(state_dir, Snapshot::v2_default(), uuid);
        std::fs::write(
            state_dir.join(guard_core::paths::TRUSTED_RULE_SIGNERS_FILENAME),
            "other\tsecure-enclave\t0001\ttest\n",
        )
        .unwrap();
        let manifest_path = guard_daemon::state_dir::run_manifest_path(state_dir, uuid);
        unsafe {
            std::env::set_var("STT_GUARD_SNAPSHOT_MANIFEST", &manifest_path);
            std::env::set_var("STT_GUARD_STATE_DIR", state_dir);
        }
        let r = load_from_env();
        assert!(
            matches!(r, Err(LoadError::SnapshotSignerUntrusted)),
            "expected SnapshotSignerUntrusted, got {r:?}"
        );
    });
}

// --- M004-S02 HMAC integrity tests ---

#[test]
fn hmac_happy_path_with_signed_manifest() {
    use guard_daemon::state_dir::ensure_runs_dir;

    let _t = with_fake_home(|state_dir| {
        ensure_runs_dir(state_dir).unwrap();
        hmac_key::generate_and_store(state_dir).unwrap();

        let snap = Snapshot::v2_default();
        let uuid = "hmac-test-0001";
        let pub_ = publish_signed_run(state_dir, snap, uuid);
        assert!(
            pub_.hmac_hex.is_some(),
            "publish_run must produce hmac when key present"
        );

        let manifest_path = guard_daemon::state_dir::run_manifest_path(state_dir, uuid);
        unsafe {
            std::env::set_var("STT_GUARD_SNAPSHOT_MANIFEST", &manifest_path);
            std::env::set_var("STT_GUARD_STATE_DIR", state_dir);
        }
        let loaded = load_from_env().expect("HMAC happy path");
        assert_eq!(loaded.schema_version, 2);
        assert!(!loaded.entries.is_empty());
    });
}

#[test]
fn hmac_fail_closed_on_tampered_hmac() {
    use guard_daemon::state_dir::ensure_runs_dir;

    let _t = with_fake_home(|state_dir| {
        ensure_runs_dir(state_dir).unwrap();
        hmac_key::generate_and_store(state_dir).unwrap();

        let snap = Snapshot::v2_default();
        let uuid = "hmac-test-0002";
        let _pub = publish_signed_run(state_dir, snap, uuid);

        // Tamper with HMAC in the manifest
        let manifest_path = guard_daemon::state_dir::run_manifest_path(state_dir, uuid);
        let text = std::fs::read_to_string(&manifest_path).unwrap();
        let tampered = text.replace(
            "hmac=",
            "hmac=0000000000000000000000000000000000000000000000000000000000000000\nold_hmac=",
        );
        std::fs::write(&manifest_path, &tampered).unwrap();

        unsafe {
            std::env::set_var("STT_GUARD_SNAPSHOT_MANIFEST", &manifest_path);
            std::env::set_var("STT_GUARD_STATE_DIR", state_dir);
        }
        let r = load_from_env();
        assert!(
            matches!(r, Err(LoadError::HmacMismatch)),
            "expected HmacMismatch, got: {r:?}"
        );
    });
}

#[test]
fn hmac_fail_closed_when_key_exists_but_manifest_has_no_hmac() {
    let _t = with_fake_home(|state_dir| {
        // Publish signed manifest before key exists, then create key so loader requires HMAC.
        let snap = Snapshot::v2_default();
        let uuid = "hmac-test-0003";
        let _pub = publish_signed_run(state_dir, snap, uuid);
        hmac_key::generate_and_store(state_dir).unwrap();

        unsafe {
            std::env::set_var(
                "STT_GUARD_SNAPSHOT_MANIFEST",
                guard_daemon::state_dir::run_manifest_path(state_dir, uuid),
            );
            std::env::set_var("STT_GUARD_STATE_DIR", state_dir);
        }
        let r = load_from_env();
        assert!(
            matches!(r, Err(LoadError::HmacMissing)),
            "expected HmacMissing, got: {r:?}"
        );
    });
}

#[test]
fn no_hmac_key_skips_verification() {
    let _t = with_fake_home(|state_dir| {
        // No key generated — legacy mode, HMAC check should be skipped
        let snap = Snapshot::v2_default();
        let uuid = "hmac-test-0004";
        let _pub = publish_signed_run(state_dir, snap, uuid);

        unsafe {
            std::env::set_var(
                "STT_GUARD_SNAPSHOT_MANIFEST",
                guard_daemon::state_dir::run_manifest_path(state_dir, uuid),
            );
            std::env::set_var("STT_GUARD_STATE_DIR", state_dir);
        }
        let loaded = load_from_env().expect("no-key should skip HMAC check");
        assert_eq!(loaded.schema_version, 2);
    });
}
