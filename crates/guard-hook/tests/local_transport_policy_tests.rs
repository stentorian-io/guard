#![cfg(target_os = "macos")]

use guard_core::{AllowlistEntry, Verdict};
use guard_hook::test_decide_for_sockaddr;

#[test]
fn unix_domain_socket_connect_fails_closed() {
    let mut addr: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    #[cfg(target_os = "macos")]
    {
        addr.sun_len = u8::try_from(std::mem::size_of::<libc::sockaddr_un>()).unwrap_or(0);
    }
    addr.sun_family = libc::sa_family_t::try_from(libc::AF_UNIX).unwrap_or(0);

    let addrlen = libc::socklen_t::try_from(std::mem::size_of::<libc::sockaddr_un>()).unwrap_or(0);
    let verdict = unsafe {
        test_decide_for_sockaddr(
            Vec::<AllowlistEntry>::new(),
            &raw mut addr as *const libc::sockaddr,
            addrlen,
        )
    };

    assert_eq!(verdict, Verdict::Deny);
}
