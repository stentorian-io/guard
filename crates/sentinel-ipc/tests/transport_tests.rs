//! End-to-end transport tests using `socketpair(AF_UNIX, SOCK_STREAM)` —
//! the same primitive the Wave 0 spike verified for LOCAL_PEERTOKEN.

use sentinel_ipc::frame::{read_frame, write_frame};
use sentinel_ipc::transport::{peer_audit_token, peer_identity};
use sentinel_ipc::{IPC_SCHEMA_V1, RegisterRoot, Reply};
use std::os::unix::io::FromRawFd;
use std::os::unix::net::UnixStream;

fn make_pair() -> (UnixStream, UnixStream) {
    let mut sv: [libc::c_int; 2] = [-1, -1];
    let r = unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, sv.as_mut_ptr()) };
    assert_eq!(r, 0, "socketpair failed: {}", std::io::Error::last_os_error());
    let a = unsafe { UnixStream::from_raw_fd(sv[0]) };
    let b = unsafe { UnixStream::from_raw_fd(sv[1]) };
    (a, b)
}

#[test]
fn register_root_traverses_a_socketpair() {
    let (mut a, mut b) = make_pair();
    let token = sentinel_core::AuditToken::synthetic([1, 2, 3, 4, 5, 7777, 0, 11]);
    let msg = RegisterRoot::new(token);
    write_frame(&mut a, &msg).expect("write");
    let received: RegisterRoot = read_frame(&mut b).expect("read");
    assert_eq!(received, msg);
    assert_eq!(received.schema_version, IPC_SCHEMA_V1);
    let received_token: sentinel_core::AuditToken = received.audit_token.into();
    assert_eq!(received_token.val, token.val);
}

#[test]
fn reply_ack_traverses_back() {
    let (mut a, mut b) = make_pair();
    write_frame(&mut b, &Reply::ack()).expect("write");
    let r: Reply = read_frame(&mut a).expect("read");
    assert!(matches!(r, Reply::Ack { .. }));
}

/// LOCAL_PEERTOKEN over a socketpair returns a token whose val[5] (pid) equals
/// the test process's pid (since both ends of the pair are this process).
/// Mirrors the spike's A1 check at the wire layer.
#[test]
fn peer_audit_token_returns_self_pid_over_socketpair() {
    let (a, _b) = make_pair();
    let token = peer_audit_token(&a).expect("peer_audit_token");
    let my_pid = unsafe { libc::getpid() } as u32;
    assert_eq!(token.val[5], my_pid, "LOCAL_PEERTOKEN val[5] should be peer pid (== self pid for socketpair)");
}

#[test]
fn peer_identity_yields_verified() {
    let (a, _b) = make_pair();
    let id = peer_identity(&a).expect("peer_identity");
    let key = id.as_policy_key().expect("Verified should yield policy key");
    let my_pid = unsafe { libc::getpid() } as u32;
    assert_eq!(key.val[5], my_pid);
}
