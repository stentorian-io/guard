use sentinel_core::{Snapshot, SCHEMA_V1, AllowlistEntry, match_hostname, Verdict};

#[test]
fn phase1_default_contains_minimal_entries_per_d18() {
    let s = Snapshot::phase1_default();
    assert_eq!(s.schema_version, SCHEMA_V1);
    assert!(s.entries.iter().any(|e| matches!(e, AllowlistEntry::Ip(s) if s == "127.0.0.1")));
    assert!(s.entries.iter().any(|e| matches!(e, AllowlistEntry::Ip(s) if s == "::1")));
    assert!(s.entries.iter().any(|e| matches!(e, AllowlistEntry::Exact(s) if s == "registry.npmjs.org")));
    assert!(s.entries.iter().any(|e| matches!(e, AllowlistEntry::Exact(s) if s == "sentinel-test-marker.invalid")));
}

#[test]
fn cbor_roundtrip_preserves_fields() {
    let original = Snapshot::phase1_default();
    let bytes = original.encode().expect("encode");
    let decoded = Snapshot::decode(&bytes).expect("decode");
    assert_eq!(original, decoded);
}

#[test]
fn decode_rejects_wrong_schema_version() {
    use sentinel_core::Error;
    // Construct a Snapshot with schema_version=99 by manually serializing.
    let bad = Snapshot { schema_version: 99, generated_at_unix_ms: 0, entries: vec![] };
    let mut bytes = Vec::new();
    ciborium::ser::into_writer(&bad, &mut bytes).unwrap();
    let result = Snapshot::decode(&bytes);
    match result {
        Err(Error::SchemaVersionMismatch { expected, got }) => {
            assert_eq!(expected, SCHEMA_V1);
            assert_eq!(got, 99);
        }
        other => panic!("expected SchemaVersionMismatch, got {:?}", other),
    }
}

#[test]
fn decode_rejects_garbage_bytes() {
    let result = Snapshot::decode(b"not a CBOR document");
    assert!(result.is_err(), "garbage bytes must be rejected");
}

#[test]
fn phase1_default_matches_localhost_and_npmjs_via_matcher() {
    let s = Snapshot::phase1_default();
    assert_eq!(match_hostname(&s.entries, b"localhost"), Verdict::Allow);
    assert_eq!(match_hostname(&s.entries, b"registry.npmjs.org"), Verdict::Allow);
    assert_eq!(match_hostname(&s.entries, b"evil.example.com"), Verdict::Deny);
}
