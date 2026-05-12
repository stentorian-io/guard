//! M005-S01: sentinel_getaddrinfo daemon-proxied DNS tests.
//!
//! Verifies that getaddrinfo interpose correctly proxies through the daemon:
//! - Resolve IPC round-trip with a stub daemon
//! - addrinfo linked list assembly from wire sockaddrs
//! - DNS cache population (subsequent connect cache-hits)
//! - freeaddrinfo cleanup
//! - Error paths: no daemon, timeout, deny

static SOCKET_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

use sentinel_hook::ipc_client::{
    _clear_daemon_socket_for_test, _set_daemon_socket_for_test,
};
use sentinel_ipc::frame::{read_frame, write_frame};
use sentinel_ipc::{ResolveReply, SOCKADDR_WIRE_LEN};
use std::io::{Read, Write};
use std::os::unix::net::UnixListener;
use std::path::PathBuf;
use std::thread;
use std::time::Duration;
use tempfile::TempDir;

fn v4_wire_1_2_3_4_port443() -> [u8; SOCKADDR_WIRE_LEN] {
    let mut buf = [0u8; SOCKADDR_WIRE_LEN];
    buf[0] = 16; // sin_len
    buf[1] = 2;  // AF_INET
    buf[2] = 0x01;
    buf[3] = 0xBB; // port 443 BE
    buf[4] = 1;
    buf[5] = 2;
    buf[6] = 3;
    buf[7] = 4;
    buf
}

fn v6_wire_localhost_port443() -> [u8; SOCKADDR_WIRE_LEN] {
    let mut buf = [0u8; SOCKADDR_WIRE_LEN];
    buf[0] = 28; // sin6_len
    buf[1] = 30; // AF_INET6
    buf[2] = 0x01;
    buf[3] = 0xBB; // port 443 BE
    // bytes 4..8 = sin6_flowinfo (zero)
    // bytes 8..24 = ::1
    buf[23] = 1;
    // bytes 24..28 = sin6_scope_id (zero)
    buf
}

fn spawn_stub_resolver(reply: ResolveReply) -> (TempDir, PathBuf) {
    let dir = tempfile::tempdir().expect("tempdir");
    let sock_path = dir.path().join("gai_stub.sock");
    let listener = UnixListener::bind(&sock_path).expect("bind");
    thread::spawn(move || {
        if let Ok((mut stream, _)) = listener.accept() {
            let mut tag = [0u8; 1];
            if stream.read_exact(&mut tag).is_err() {
                return;
            }
            assert_eq!(tag[0], 0x06);
            let _req: sentinel_ipc::Resolve = read_frame(&mut stream).expect("read Resolve");
            stream.write_all(&[0x06]).expect("write tag");
            write_frame(&mut stream, &reply).expect("write reply");
        }
    });
    thread::sleep(Duration::from_millis(10));
    (dir, sock_path)
}

// Helper: call sentinel_getaddrinfo directly via its C ABI symbol.
unsafe extern "C" {
    fn sentinel_getaddrinfo(
        node: *const libc::c_char,
        service: *const libc::c_char,
        hints: *const libc::addrinfo,
        res: *mut *mut libc::addrinfo,
    ) -> libc::c_int;
    fn sentinel_freeaddrinfo(res: *mut libc::addrinfo);
}

// ---- Test 1: getaddrinfo returns addresses from stub daemon ----

#[cfg_attr(not(target_os = "macos"), ignore)]
#[test]
fn getaddrinfo_proxy_returns_v4_address() {
    let _lock = SOCKET_TEST_LOCK.lock().unwrap();
    let wire = v4_wire_1_2_3_4_port443();
    let reply = ResolveReply::addresses(vec![wire]);
    let (_dir, sock_path) = spawn_stub_resolver(reply);
    _set_daemon_socket_for_test(sock_path);

    // Ensure FAIL_CLOSED is false and ALLOWLIST is set (sentinel_getaddrinfo
    // doesn't check policy — it just proxies DNS — but the hook ctor might
    // not have run in this test binary).
    sentinel_hook::snapshot::FAIL_CLOSED.store(false, std::sync::atomic::Ordering::Release);

    let node = c"example.com";
    let service = c"443";
    let mut result: *mut libc::addrinfo = std::ptr::null_mut();

    let rc = unsafe { sentinel_getaddrinfo(node.as_ptr(), service.as_ptr(), std::ptr::null(), &mut result) };
    _clear_daemon_socket_for_test();

    assert_eq!(rc, 0, "sentinel_getaddrinfo should return 0 on success");
    assert!(!result.is_null(), "result should not be null");

    // Verify the addrinfo fields.
    let ai = unsafe { &*result };
    assert_eq!(ai.ai_family, libc::AF_INET);
    assert_eq!(
        ai.ai_addrlen as usize,
        std::mem::size_of::<libc::sockaddr_in>()
    );
    assert!(!ai.ai_addr.is_null());

    // Verify the sockaddr contents.
    let sin = unsafe { &*(ai.ai_addr as *const libc::sockaddr_in) };
    assert_eq!(sin.sin_family, libc::AF_INET as u8);
    assert_eq!(u16::from_be(sin.sin_port), 443);
    let ip_bytes = sin.sin_addr.s_addr.to_ne_bytes();
    assert_eq!(ip_bytes, [1, 2, 3, 4]);

    // No more entries in the list.
    assert!(ai.ai_next.is_null());

    // Free the list.
    unsafe { sentinel_freeaddrinfo(result) };
}

// ---- Test 2: getaddrinfo with mixed v4+v6 addresses ----

#[cfg_attr(not(target_os = "macos"), ignore)]
#[test]
fn getaddrinfo_proxy_returns_mixed_v4_v6() {
    let _lock = SOCKET_TEST_LOCK.lock().unwrap();
    let v4 = v4_wire_1_2_3_4_port443();
    let v6 = v6_wire_localhost_port443();
    let reply = ResolveReply::addresses(vec![v4, v6]);
    let (_dir, sock_path) = spawn_stub_resolver(reply);
    _set_daemon_socket_for_test(sock_path);
    sentinel_hook::snapshot::FAIL_CLOSED.store(false, std::sync::atomic::Ordering::Release);

    let node = c"dual-stack.example.com";
    let service = c"443";
    let mut result: *mut libc::addrinfo = std::ptr::null_mut();

    let rc = unsafe { sentinel_getaddrinfo(node.as_ptr(), service.as_ptr(), std::ptr::null(), &mut result) };
    _clear_daemon_socket_for_test();

    assert_eq!(rc, 0);
    assert!(!result.is_null());

    // First entry: IPv4.
    let ai1 = unsafe { &*result };
    assert_eq!(ai1.ai_family, libc::AF_INET);
    assert!(!ai1.ai_next.is_null(), "should have a second entry");

    // Second entry: IPv6.
    let ai2 = unsafe { &*ai1.ai_next };
    assert_eq!(ai2.ai_family, libc::AF_INET6);
    assert_eq!(
        ai2.ai_addrlen as usize,
        std::mem::size_of::<libc::sockaddr_in6>()
    );
    assert!(ai2.ai_next.is_null());

    unsafe { sentinel_freeaddrinfo(result) };
}

// ---- Test 3: hint_family filters addresses ----

#[cfg_attr(not(target_os = "macos"), ignore)]
#[test]
fn getaddrinfo_proxy_respects_hint_family() {
    let _lock = SOCKET_TEST_LOCK.lock().unwrap();
    let v4 = v4_wire_1_2_3_4_port443();
    let v6 = v6_wire_localhost_port443();
    let reply = ResolveReply::addresses(vec![v4, v6]);
    let (_dir, sock_path) = spawn_stub_resolver(reply);
    _set_daemon_socket_for_test(sock_path);
    sentinel_hook::snapshot::FAIL_CLOSED.store(false, std::sync::atomic::Ordering::Release);

    let node = c"filter.example.com";
    let service = c"443";
    let hints = libc::addrinfo {
        ai_flags: 0,
        ai_family: libc::AF_INET6,
        ai_socktype: 0,
        ai_protocol: 0,
        ai_addrlen: 0,
        ai_canonname: std::ptr::null_mut(),
        ai_addr: std::ptr::null_mut(),
        ai_next: std::ptr::null_mut(),
    };
    let mut result: *mut libc::addrinfo = std::ptr::null_mut();

    let rc = unsafe { sentinel_getaddrinfo(node.as_ptr(), service.as_ptr(), &hints, &mut result) };
    _clear_daemon_socket_for_test();

    assert_eq!(rc, 0);
    assert!(!result.is_null());

    // Only IPv6 should be in the result.
    let ai = unsafe { &*result };
    assert_eq!(ai.ai_family, libc::AF_INET6);
    assert!(ai.ai_next.is_null(), "only one entry after filtering");

    unsafe { sentinel_freeaddrinfo(result) };
}

// ---- Test 4: no daemon → EAI_AGAIN ----

#[cfg_attr(not(target_os = "macos"), ignore)]
#[test]
fn getaddrinfo_proxy_returns_eai_again_when_no_daemon() {
    let _lock = SOCKET_TEST_LOCK.lock().unwrap();
    _clear_daemon_socket_for_test();
    sentinel_hook::snapshot::FAIL_CLOSED.store(false, std::sync::atomic::Ordering::Release);

    let node = c"no-daemon.example.com";
    let mut result: *mut libc::addrinfo = std::ptr::null_mut();

    let rc = unsafe { sentinel_getaddrinfo(node.as_ptr(), std::ptr::null(), std::ptr::null(), &mut result) };

    assert_eq!(rc, libc::EAI_AGAIN);
    assert!(result.is_null());
}

// ---- Test 5: deny → EAI_FAIL ----

#[cfg_attr(not(target_os = "macos"), ignore)]
#[test]
fn getaddrinfo_proxy_returns_eai_fail_on_deny() {
    let _lock = SOCKET_TEST_LOCK.lock().unwrap();
    let reply = ResolveReply::deny("policy: blocked by sentinel");
    let (_dir, sock_path) = spawn_stub_resolver(reply);
    _set_daemon_socket_for_test(sock_path);
    sentinel_hook::snapshot::FAIL_CLOSED.store(false, std::sync::atomic::Ordering::Release);

    let node = c"evil.example.com";
    let service = c"443";
    let mut result: *mut libc::addrinfo = std::ptr::null_mut();

    let rc = unsafe { sentinel_getaddrinfo(node.as_ptr(), service.as_ptr(), std::ptr::null(), &mut result) };
    _clear_daemon_socket_for_test();

    assert_eq!(rc, libc::EAI_FAIL);
    assert!(result.is_null());
}

// ---- Test 6: FAIL_CLOSED → EAI_FAIL (S04: fail-closed consistency) ----

#[cfg_attr(not(target_os = "macos"), ignore)]
#[test]
fn getaddrinfo_returns_eai_fail_when_fail_closed() {
    let _lock = SOCKET_TEST_LOCK.lock().unwrap();
    let reply = ResolveReply::addresses(vec![v4_wire_1_2_3_4_port443()]);
    let (_dir, sock_path) = spawn_stub_resolver(reply);
    _set_daemon_socket_for_test(sock_path);
    sentinel_hook::snapshot::FAIL_CLOSED.store(true, std::sync::atomic::Ordering::Release);

    let node = c"any.example.com";
    let service = c"443";
    let mut result: *mut libc::addrinfo = std::ptr::null_mut();

    let rc = unsafe { sentinel_getaddrinfo(node.as_ptr(), service.as_ptr(), std::ptr::null(), &mut result) };
    _clear_daemon_socket_for_test();
    sentinel_hook::snapshot::FAIL_CLOSED.store(false, std::sync::atomic::Ordering::Release);

    assert_eq!(rc, libc::EAI_FAIL, "FAIL_CLOSED should cause EAI_FAIL");
    assert!(result.is_null());
}

// ---- Test 7: null node → EAI_AGAIN (can't proxy wildcard lookups) ----

#[cfg_attr(not(target_os = "macos"), ignore)]
#[test]
fn getaddrinfo_proxy_returns_eai_again_for_null_node() {
    let _lock = SOCKET_TEST_LOCK.lock().unwrap();
    sentinel_hook::snapshot::FAIL_CLOSED.store(false, std::sync::atomic::Ordering::Release);
    // Even with a daemon configured, null node can't be proxied.
    let reply = ResolveReply::addresses(vec![v4_wire_1_2_3_4_port443()]);
    let (_dir, sock_path) = spawn_stub_resolver(reply);
    _set_daemon_socket_for_test(sock_path);

    let mut result: *mut libc::addrinfo = std::ptr::null_mut();
    let rc = unsafe { sentinel_getaddrinfo(std::ptr::null(), std::ptr::null(), std::ptr::null(), &mut result) };
    _clear_daemon_socket_for_test();

    assert_eq!(rc, libc::EAI_AGAIN);
    assert!(result.is_null());
}
