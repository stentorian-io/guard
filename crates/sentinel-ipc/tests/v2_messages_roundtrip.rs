use sentinel_ipc::*;

fn cbor_roundtrip<T>(v: &T) -> T
where
    T: serde::Serialize + serde::de::DeserializeOwned + std::fmt::Debug + PartialEq,
{
    let mut buf = Vec::new();
    ciborium::ser::into_writer(v, &mut buf).expect("encode");
    ciborium::de::from_reader(buf.as_slice()).expect("decode")
}

fn token() -> AuditTokenWire {
    AuditTokenWire {
        val: [1, 2, 3, 4, 5, 6, 7, 8],
    }
}

#[test]
fn schema_constants() {
    assert_eq!(IPC_SCHEMA_V1, 1);
    assert_eq!(IPC_SCHEMA_V2, 2);
    assert_eq!(IPC_SCHEMA_V5, 5);
}

#[test]
fn frozen_register_root_still_uses_v1() {
    // v0.1 contract preserved.
    let id = sentinel_core::AuditToken { val: [9; 8] };
    let r = RegisterRoot::new(id);
    assert_eq!(r.schema_version, IPC_SCHEMA_V1);
}

#[test]
fn prepare_snapshot_roundtrip() {
    let m = PrepareSnapshot::new("/Users/x/proj");
    assert_eq!(m.schema_version, IPC_SCHEMA_V2);
    assert_eq!(cbor_roundtrip(&m), m);
}

#[test]
fn snapshot_reply_variants_roundtrip() {
    let ok = SnapshotReply::ok("/path/to.manifest", "11111111-2222-3333-4444-555555555555");
    assert_eq!(cbor_roundtrip(&ok), ok);
    let err = SnapshotReply::err("walk-up failed");
    assert_eq!(cbor_roundtrip(&err), err);
}

#[test]
fn fork_event_and_ack_roundtrip() {
    let ev = ForkEvent::new(token(), 4242, 7);
    assert_eq!(ev.schema_version, IPC_SCHEMA_V2);
    assert_eq!(cbor_roundtrip(&ev), ev);
    assert_eq!(cbor_roundtrip(&ForkAck::ok()), ForkAck::ok());
    let e = ForkAck::err("daemon overloaded");
    assert_eq!(cbor_roundtrip(&e), e);
}

#[test]
fn exec_event_and_ack_roundtrip() {
    let ev = ExecEvent::new(token(), b"/usr/bin/python3".to_vec());
    assert_eq!(ev.schema_version, IPC_SCHEMA_V2);
    assert_eq!(cbor_roundtrip(&ev), ev);
    assert_eq!(cbor_roundtrip(&ExecAck::ok()), ExecAck::ok());
}

#[test]
fn exec_event_max_target_path_const_is_1024() {
    assert_eq!(ExecEvent::MAX_TARGET_PATH, 1024);
}

#[test]
fn trace_spawned_roundtrip() {
    let ev = TraceSpawned::new(
        token(),
        4242,
        99,
        b"/tmp/t3-bin".to_vec(),
        "syscall-instruction",
    );
    assert_eq!(ev.schema_version, IPC_SCHEMA_V5);
    assert_eq!(TraceSpawned::MAX_TARGET_PATH, 1024);
    assert_eq!(cbor_roundtrip(&ev), ev);
    assert_eq!(
        cbor_roundtrip(&TraceSpawnedAck::ok()),
        TraceSpawnedAck::ok()
    );
    let err = TraceSpawnedAck::err("ptrace attach failed");
    assert_eq!(cbor_roundtrip(&err), err);
}

#[test]
fn dylib_loaded_roundtrip() {
    let m = DylibLoaded::new(token());
    assert_eq!(m.schema_version, IPC_SCHEMA_V2);
    assert_eq!(cbor_roundtrip(&m), m);
    assert_eq!(cbor_roundtrip(&DylibLoadedAck::ok()), DylibLoadedAck::ok());
}

#[test]
fn resolve_roundtrip() {
    let m = Resolve::new("registry.npmjs.org", 443);
    assert_eq!(m.schema_version, IPC_SCHEMA_V2);
    assert_eq!(cbor_roundtrip(&m), m);

    let addrs = ResolveReply::addresses(vec![[0xab; SOCKADDR_WIRE_LEN]]);
    assert_eq!(cbor_roundtrip(&addrs), addrs);
    let deny = ResolveReply::deny("169.254.169.254 metadata host");
    assert_eq!(cbor_roundtrip(&deny), deny);
    let err = ResolveReply::err("getaddrinfo: NXDOMAIN");
    assert_eq!(cbor_roundtrip(&err), err);
}

#[test]
fn sockaddr_wire_len_is_28() {
    assert_eq!(SOCKADDR_WIRE_LEN, 28);
}
