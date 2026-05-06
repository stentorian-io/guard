use sentinel_daemon::handlers::resolve::handle_resolve;
use sentinel_ipc::ResolveReply;

#[test]
fn resolve_localhost_returns_addresses() {
    let r = handle_resolve("localhost", 80);
    match r {
        ResolveReply::Addresses { addrs, .. } => {
            assert!(
                !addrs.is_empty(),
                "localhost should resolve to at least one address"
            );
            // Second byte is family (AF_INET=2 or AF_INET6=30 on Darwin).
            for a in &addrs {
                let family = a[1];
                assert!(
                    family == libc::AF_INET as u8 || family == libc::AF_INET6 as u8,
                    "unexpected family {family}"
                );
            }
        }
        other => panic!("expected Addresses; got {other:?}"),
    }
}

#[test]
fn resolve_invalid_host_returns_err() {
    let r = handle_resolve("this-host-does-not-exist-12345.invalid", 80);
    assert!(matches!(r, ResolveReply::Err { .. }));
}
