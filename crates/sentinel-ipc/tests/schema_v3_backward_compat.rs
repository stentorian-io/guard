//! Phase 3 plan 03-02: backward-compat decode tests for V2 messages under V3 schemas.
//! Verifies that V2-encoded messages (without new fields) still decode correctly
//! under V3 schema structs using #[serde(default)].

use sentinel_ipc::{AuditTokenWire, ExecEvent, IPC_SCHEMA_V2, IPC_SCHEMA_V3, PrepareSnapshot};

// Shadow structs used to encode a "V2-only" message (without new fields)
#[derive(serde::Serialize)]
struct PrepareSnapshotV2Only {
    schema_version: u16,
    cwd: String,
}

#[derive(serde::Serialize)]
struct ExecEventV2Only {
    schema_version: u16,
    audit_token: AuditTokenWire,
    #[serde(with = "serde_bytes")]
    target_path: Vec<u8>,
}

#[test]
fn v2_prepare_snapshot_decodes_under_v3_struct() {
    // Encode a V2-only PrepareSnapshot (no is_tty, no baseline_mode).
    // Decoding under V3 struct must succeed and default new fields to false.
    let v2 = PrepareSnapshotV2Only {
        schema_version: IPC_SCHEMA_V2,
        cwd: "/tmp".into(),
    };
    let mut bytes = Vec::new();
    ciborium::into_writer(&v2, &mut bytes).expect("encode v2 PrepareSnapshot");
    let decoded: PrepareSnapshot =
        ciborium::from_reader(bytes.as_slice()).expect("decode v2 under v3 schema");
    assert_eq!(decoded.schema_version, IPC_SCHEMA_V2);
    assert_eq!(decoded.cwd, "/tmp");
    assert!(!decoded.is_tty, "is_tty must default false for V2 message");
    assert!(
        !decoded.baseline_mode,
        "baseline_mode must default false for V2 message"
    );
}

#[test]
fn v3_prepare_snapshot_round_trip() {
    let original = PrepareSnapshot::new_v3("/cwd", true, true);
    let mut bytes = Vec::new();
    ciborium::into_writer(&original, &mut bytes).expect("encode v3 PrepareSnapshot");
    let decoded: PrepareSnapshot =
        ciborium::from_reader(bytes.as_slice()).expect("decode v3 PrepareSnapshot");
    assert_eq!(decoded, original);
    assert_eq!(decoded.schema_version, IPC_SCHEMA_V3);
    assert!(decoded.is_tty);
    assert!(decoded.baseline_mode);
}

#[test]
fn v2_exec_event_decodes_under_v3_struct() {
    // Encode a V2-only ExecEvent (no pm_env).
    // Decoding under V3 struct must succeed and default pm_env to empty Vec.
    let v2 = ExecEventV2Only {
        schema_version: IPC_SCHEMA_V2,
        audit_token: AuditTokenWire { val: [0u32; 8] },
        target_path: b"/usr/bin/foo".to_vec(),
    };
    let mut bytes = Vec::new();
    ciborium::into_writer(&v2, &mut bytes).expect("encode v2 ExecEvent");
    let decoded: ExecEvent =
        ciborium::from_reader(bytes.as_slice()).expect("decode v2 ExecEvent under v3 schema");
    assert_eq!(decoded.schema_version, IPC_SCHEMA_V2);
    assert_eq!(decoded.target_path, b"/usr/bin/foo");
    assert!(decoded.pm_env.is_empty(), "pm_env must default to empty for V2 message");
}

#[test]
fn v3_exec_event_round_trip_preserves_pm_env_order() {
    let pm = vec![
        ("npm_package_name".to_string(), "lodash".to_string()),
        ("npm_lifecycle_event".to_string(), "postinstall".to_string()),
    ];
    let original =
        ExecEvent::new_v3(AuditTokenWire { val: [0u32; 8] }, b"/usr/bin/node".to_vec(), pm.clone());
    let mut bytes = Vec::new();
    ciborium::into_writer(&original, &mut bytes).expect("encode v3 ExecEvent");
    let decoded: ExecEvent = ciborium::from_reader(bytes.as_slice()).expect("decode v3 ExecEvent");
    assert_eq!(decoded.pm_env, pm, "pm_env order must be preserved (Vec, not HashMap)");
    assert_eq!(decoded.schema_version, IPC_SCHEMA_V3);
}
