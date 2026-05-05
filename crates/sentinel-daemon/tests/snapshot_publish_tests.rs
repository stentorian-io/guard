use sentinel_core::{Snapshot, SCHEMA_V1};
use sentinel_daemon::manifest::{self, ParsedManifest};
use sentinel_daemon::snapshot::publish;
use sentinel_daemon::state_dir::{ensure_state_dir, manifest_path};
use sha2::{Digest, Sha256};
use std::os::unix::fs::PermissionsExt;

#[test]
fn publish_then_read_back_with_digest_verification() {
    let tmp = tempfile::tempdir().unwrap();
    let state_dir = tmp.path();
    ensure_state_dir(state_dir).unwrap();

    let snap = Snapshot::phase1_default();
    let published = publish(state_dir, &snap, 0xCAFEBABE_DEADBEEF).expect("publish");

    // Verify file mode 0600
    let mode = std::fs::metadata(&published.path).unwrap().permissions().mode();
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

    // Verify decoded snapshot equals what we wrote
    let decoded = Snapshot::decode(&bytes).expect("decode");
    assert_eq!(decoded.schema_version, SCHEMA_V1);
    assert_eq!(decoded, snap);
}

#[test]
fn ensure_state_dir_creates_mode_0700() {
    let tmp = tempfile::tempdir().unwrap();
    let nested = tmp.path().join("Library/Application Support/Sentinel");
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
    let snap = Snapshot::phase1_default();
    let p1 = publish(state_dir, &snap, 1).unwrap();
    let p2 = publish(state_dir, &snap, 2).unwrap();
    assert_ne!(p1.path, p2.path);
    assert!(p1.path.exists() && p2.path.exists());
}
