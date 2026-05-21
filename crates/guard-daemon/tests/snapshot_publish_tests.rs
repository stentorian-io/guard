//! v0.1 fixture tests for snapshot::publish + manifest::write.
//!
//! Migrated to SCHEMA_V2 in v0.2: the v0.1 round-trip test used
//! Snapshot::v1_default() + Snapshot::decode which now rejects SCHEMA_V1
//! (v0.2 made decode fail-closed). Switching to v2_default() preserves the
//! original test intent — verify that the same bytes round-trip
//! publish → file → decode → equal — under the V2 schema discipline.

use guard_core::{SCHEMA_V2, Snapshot};
use guard_daemon::manifest::{self, ParsedManifest};
use guard_daemon::snapshot::{publish, publish_run};
use guard_daemon::state_dir::{
    ensure_runs_dir, ensure_state_dir, manifest_path, run_manifest_path, run_snapshot_path,
};
use sha2::{Digest, Sha256};
use std::os::unix::fs::PermissionsExt;

#[test]
fn publish_then_read_back_with_digest_verification() {
    let tmp = tempfile::tempdir().unwrap();
    let state_dir = tmp.path();
    ensure_state_dir(state_dir).unwrap();

    let snap = Snapshot::v2_default();
    let published = publish(state_dir, &snap, 0xCAFEBABE_DEADBEEF).expect("publish");

    // Verify file mode 0600
    let mode = std::fs::metadata(&published.path)
        .unwrap()
        .permissions()
        .mode();
    assert_eq!(mode & 0o777, 0o600, "snapshot file must be mode 0600");

    // Verify digest matches the actual file bytes
    let bytes = std::fs::read(&published.path).unwrap();
    let actual = format!("{:x}", Sha256::digest(&bytes));
    assert_eq!(actual, published.digest_hex, "digest matches file bytes");

    // Write the manifest and re-read it
    manifest::write(state_dir, &published).expect("manifest write");
    let manifest_text = std::fs::read_to_string(manifest_path(state_dir)).unwrap();
    let parsed: ParsedManifest = manifest::parse(&manifest_text).expect("parse");
    assert_eq!(parsed.digest_hex, published.digest_hex);
    assert_eq!(parsed.snapshot_path, published.path.to_string_lossy());

    // Verify decoded snapshot equals what we wrote — under SCHEMA_V2.
    let decoded = Snapshot::decode(&bytes).expect("decode");
    assert_eq!(decoded.schema_version, SCHEMA_V2);
    assert_eq!(decoded, snap);
}

#[test]
fn ensure_state_dir_creates_mode_0700() {
    let tmp = tempfile::tempdir().unwrap();
    let nested = tmp
        .path()
        .join("Library/Application Support/Stentorian Guard");
    ensure_state_dir(&nested).unwrap();
    let mode = std::fs::metadata(&nested).unwrap().permissions().mode();
    assert_eq!(mode & 0o777, 0o700, "state_dir must be mode 0700");
}

#[test]
fn manifest_parse_rejects_malformed() {
    assert!(manifest::parse("only-one-line").is_err());
    assert!(manifest::parse("/path/to/snap\nno-digest-prefix").is_err());
    assert!(manifest::parse("/path/to/snap\ndigest=not-hex").is_err());
    let valid = format!("/path/to/snap\ndigest={}", "a".repeat(64));
    assert!(manifest::parse(&valid).is_ok());
}

#[test]
fn second_publish_writes_distinct_snapshot_file() {
    let tmp = tempfile::tempdir().unwrap();
    let state_dir = tmp.path();
    ensure_state_dir(state_dir).unwrap();
    let snap = Snapshot::v2_default();
    let p1 = publish(state_dir, &snap, 1).unwrap();
    let p2 = publish(state_dir, &snap, 2).unwrap();
    assert_ne!(p1.path, p2.path);
    assert!(p1.path.exists() && p2.path.exists());
}

/// Per-run publish_run path (D-29): runs/{uuid}.cbor + runs/{uuid}.manifest
/// written atomically; manifest references the snapshot path; both files
/// are mode 0600; bytes round-trip Snapshot::decode under SCHEMA_V2.
#[test]
fn publish_run_writes_per_run_files_with_manifest() {
    let tmp = tempfile::tempdir().unwrap();
    let state_dir = tmp.path();
    ensure_state_dir(state_dir).unwrap();
    ensure_runs_dir(state_dir).unwrap();

    let snap = Snapshot::v2_default();
    let uuid = "00000000-0000-0000-0000-000000000001";
    let pub_ = publish_run(state_dir, &snap, uuid).expect("publish_run");

    // Snapshot file lives at runs/{uuid}.cbor with mode 0600.
    let expected_snap = run_snapshot_path(state_dir, uuid);
    assert_eq!(pub_.path, expected_snap);
    assert!(expected_snap.exists());
    let snap_mode = std::fs::metadata(&expected_snap)
        .unwrap()
        .permissions()
        .mode();
    assert_eq!(snap_mode & 0o777, 0o600, "snapshot mode 0600");

    // Manifest file lives at runs/{uuid}.manifest with mode 0600.
    let expected_manifest = run_manifest_path(state_dir, uuid);
    assert!(expected_manifest.exists());
    let m_mode = std::fs::metadata(&expected_manifest)
        .unwrap()
        .permissions()
        .mode();
    assert_eq!(m_mode & 0o777, 0o600, "manifest mode 0600");

    // Manifest contents reference the snapshot path + digest.
    let manifest_text = std::fs::read_to_string(&expected_manifest).unwrap();
    let parsed = manifest::parse(&manifest_text).expect("parse manifest");
    assert_eq!(parsed.snapshot_path, expected_snap.to_string_lossy());
    assert_eq!(parsed.digest_hex, pub_.digest_hex);

    // Bytes round-trip Snapshot::decode under SCHEMA_V2.
    let bytes = std::fs::read(&expected_snap).unwrap();
    let decoded = Snapshot::decode(&bytes).expect("decode");
    assert_eq!(decoded.schema_version, SCHEMA_V2);
    assert_eq!(decoded, snap);
}
