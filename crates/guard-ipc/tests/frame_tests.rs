use guard_ipc::frame::{MAX_FRAME_BYTES, read_frame, write_frame};
use guard_ipc::{AuditTokenWire, IPC_SCHEMA_V1, IpcError, RegisterRoot};

#[test]
fn register_root_roundtrip_through_framing() {
    let msg = RegisterRoot {
        schema_version: IPC_SCHEMA_V1,
        audit_token: AuditTokenWire {
            val: [1, 2, 3, 4, 5, 4242, 7, 99],
        },
        run_uuid: Some("run-123".to_string()),
        pm_env: vec![("npm_package_name".to_string(), "ua-parser-js".to_string())],
    };
    let mut buf: Vec<u8> = Vec::new();
    write_frame(&mut buf, &msg).expect("write");
    let mut cursor = std::io::Cursor::new(buf);
    let decoded: RegisterRoot = read_frame(&mut cursor).expect("read");
    assert_eq!(msg, decoded);
}

#[test]
fn audit_token_8_u32_preserved_exactly() {
    let original =
        guard_core::AuditToken::synthetic([0xAAAAAAAA, 0, 0, 0, 0, 0xBBBBBBBB, 0, 0xCCCCCCCC]);
    let wire = AuditTokenWire::from(original);
    let back: guard_core::AuditToken = wire.into();
    assert_eq!(original.val, back.val);
}

#[test]
fn oversized_length_rejected() {
    // Construct a frame with a length prefix larger than MAX_FRAME_BYTES.
    let oversized = MAX_FRAME_BYTES + 1;
    let mut buf: Vec<u8> = Vec::new();
    buf.extend_from_slice(&oversized.to_be_bytes());
    // Don't bother filling the rest — read_frame must reject before reading payload.
    let mut cursor = std::io::Cursor::new(buf);
    let result: Result<RegisterRoot, _> = read_frame(&mut cursor);
    match result {
        Err(IpcError::FrameTooLarge { got, max }) => {
            assert_eq!(got, oversized);
            assert_eq!(max, MAX_FRAME_BYTES);
        }
        other => panic!("expected FrameTooLarge, got {:?}", other),
    }
}

#[test]
fn garbage_cbor_after_valid_prefix_returns_codec_error() {
    let mut buf: Vec<u8> = Vec::new();
    buf.extend_from_slice(&(8u32).to_be_bytes());
    buf.extend_from_slice(b"NOT-CBOR");
    let mut cursor = std::io::Cursor::new(buf);
    let result: Result<RegisterRoot, _> = read_frame(&mut cursor);
    assert!(
        matches!(result, Err(IpcError::Codec(_))),
        "expected Codec, got {:?}",
        result
    );
}

#[test]
fn truncated_payload_returns_io_error() {
    let mut buf: Vec<u8> = Vec::new();
    buf.extend_from_slice(&(100u32).to_be_bytes()); // claim 100 bytes
    buf.extend_from_slice(b"only-twelve!"); // provide 12
    let mut cursor = std::io::Cursor::new(buf);
    let result: Result<RegisterRoot, _> = read_frame(&mut cursor);
    assert!(
        matches!(result, Err(IpcError::Io(_))),
        "expected Io, got {:?}",
        result
    );
}

#[test]
fn reply_ack_and_err_roundtrip() {
    use guard_ipc::Reply;
    let mut buf = Vec::new();
    write_frame(&mut buf, &Reply::ack()).unwrap();
    let mut c = std::io::Cursor::new(buf.clone());
    let r: Reply = read_frame(&mut c).unwrap();
    assert!(matches!(r, Reply::Ack { schema_version } if schema_version == IPC_SCHEMA_V1));

    buf.clear();
    write_frame(&mut buf, &Reply::err("nope")).unwrap();
    let mut c = std::io::Cursor::new(buf);
    let r: Reply = read_frame(&mut c).unwrap();
    if let Reply::Err {
        schema_version,
        message,
    } = r
    {
        assert_eq!(schema_version, IPC_SCHEMA_V1);
        assert_eq!(message, "nope");
    } else {
        panic!("expected Err variant");
    }
}
