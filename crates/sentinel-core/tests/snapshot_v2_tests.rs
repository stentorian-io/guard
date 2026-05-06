use sentinel_core::{SCHEMA_V1, SCHEMA_V2, Snapshot};

#[test]
fn schema_constants_have_expected_values() {
    assert_eq!(SCHEMA_V1, 1);
    assert_eq!(SCHEMA_V2, 2);
}

#[test]
fn phase2_default_has_v2_schema_and_nonempty_entries() {
    let s = Snapshot::phase2_default();
    assert_eq!(s.schema_version, SCHEMA_V2);
    assert!(
        !s.entries.is_empty(),
        "phase2_default must seed at least loopback + registry.npmjs.org"
    );
    assert!(s.run_uuid.is_none(), "daemon-startup snapshot has no run_uuid");
    assert!(s.project_toml_path.is_none());
    assert!(s.project_toml_sha256.is_none());
}

#[test]
fn snapshot_encode_decode_roundtrip() {
    let s = Snapshot::phase2_default();
    let bytes = s.encode().expect("encode");
    let back = Snapshot::decode(&bytes).expect("decode");
    assert_eq!(s, back);
}

#[test]
fn decode_rejects_v1_schema() {
    let v1 = Snapshot::phase1_default();
    let bytes = v1.encode().expect("encode v1");
    let res = Snapshot::decode(&bytes);
    match res {
        Err(sentinel_core::Error::SchemaVersionMismatch { expected, got }) => {
            assert_eq!(expected, SCHEMA_V2);
            assert_eq!(got, SCHEMA_V1);
        }
        other => panic!("expected SchemaVersionMismatch, got {other:?}"),
    }
}

#[test]
fn decode_truncated_returns_codec_error() {
    let s = Snapshot::phase2_default();
    let bytes = s.encode().expect("encode");
    // Truncate to half its length — guaranteed malformed CBOR.
    let truncated = &bytes[..bytes.len() / 2];
    let res = Snapshot::decode(truncated);
    assert!(matches!(res, Err(sentinel_core::Error::Codec(_))));
}

#[test]
fn snapshot_with_run_uuid_roundtrips() {
    let mut s = Snapshot::phase2_default();
    s.run_uuid = Some("11111111-2222-3333-4444-555555555555".into());
    s.project_toml_path = Some("/Users/x/proj/.sentinel.toml".into());
    s.project_toml_sha256 = Some("a".repeat(64));
    let bytes = s.encode().expect("encode");
    let back = Snapshot::decode(&bytes).expect("decode");
    assert_eq!(s.run_uuid, back.run_uuid);
    assert_eq!(s.project_toml_path, back.project_toml_path);
    assert_eq!(s.project_toml_sha256, back.project_toml_sha256);
}
