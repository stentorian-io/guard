//! Peer identity primitives for connected Unix sockets.

use crate::OsError;
use guard_core::{AuditToken, ProcessIdentity};
use std::os::unix::net::UnixStream;

#[cfg(target_os = "macos")]
mod imp {
    use super::*;
    use core::ffi::c_void;
    use std::os::unix::io::AsRawFd;

    const PEER_AUDIT_TOKEN: &str = "peer audit token";

    // macOS sys/un.h constants. Verified against SDK header by the Wave 0 spike (A1).
    const SOL_LOCAL: libc::c_int = 0;
    const LOCAL_PEERTOKEN: libc::c_int = 0x006;

    pub fn peer_audit_token(stream: &UnixStream) -> Result<AuditToken, OsError> {
        let mut tok = AuditToken::synthetic([0; 8]);
        let mut len: libc::socklen_t = core::mem::size_of::<AuditToken>() as _;
        let r = unsafe {
            libc::getsockopt(
                stream.as_raw_fd(),
                SOL_LOCAL,
                LOCAL_PEERTOKEN,
                &mut tok as *mut AuditToken as *mut c_void,
                &mut len,
            )
        };
        if r < 0 {
            return Err(OsError::io(
                PEER_AUDIT_TOKEN,
                std::io::Error::last_os_error(),
            ));
        }
        if len as usize != core::mem::size_of::<AuditToken>() {
            return Err(OsError::unexpected_data(
                PEER_AUDIT_TOKEN,
                format!("LOCAL_PEERTOKEN returned unexpected length {len}"),
            ));
        }
        Ok(tok)
    }
}

#[cfg(not(target_os = "macos"))]
mod imp {
    use super::*;

    #[cfg(target_os = "linux")]
    pub fn peer_audit_token(stream: &UnixStream) -> Result<AuditToken, OsError> {
        use core::ffi::c_void;
        use std::os::unix::io::AsRawFd;

        let mut cred: libc::ucred = unsafe { core::mem::zeroed() };
        let mut len: libc::socklen_t = core::mem::size_of::<libc::ucred>() as _;
        let rc = unsafe {
            libc::getsockopt(
                stream.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_PEERCRED,
                &mut cred as *mut libc::ucred as *mut c_void,
                &mut len,
            )
        };
        if rc < 0 {
            return Err(OsError::io(
                "peer credentials",
                std::io::Error::last_os_error(),
            ));
        }
        if len as usize != core::mem::size_of::<libc::ucred>() {
            return Err(OsError::unexpected_data(
                "peer credentials",
                format!("SO_PEERCRED returned unexpected length {len}"),
            ));
        }
        if cred.pid <= 0 {
            return Err(OsError::unexpected_data(
                "peer credentials",
                format!("SO_PEERCRED returned invalid pid {}", cred.pid),
            ));
        }

        let starttime = crate::process::process_starttime_ticks(cred.pid)?;
        let pidversion = crate::process::starttime_ticks_to_pidversion(starttime);

        let mut val = [0u32; 8];
        val[1] = cred.uid;
        val[2] = cred.gid;
        val[3] = cred.uid;
        val[4] = cred.gid;
        val[5] = cred.pid as u32;
        val[7] = pidversion;
        Ok(AuditToken::synthetic(val))
    }

    #[cfg(not(target_os = "linux"))]
    pub fn peer_audit_token(_stream: &UnixStream) -> Result<AuditToken, OsError> {
        Err(OsError::unsupported("peer audit token"))
    }
}

/// Retrieve the peer process's kernel-sourced audit token from a connected
/// UnixStream.
pub fn peer_audit_token(stream: &UnixStream) -> Result<AuditToken, OsError> {
    imp::peer_audit_token(stream)
}

/// Convenience: derive a `ProcessIdentity::Verified` for a peer.
///
/// The unsafe block here is the trust-boundary annotation: `peer_audit_token`
/// is the kernel source on platforms that support this capability.
pub fn peer_identity(stream: &UnixStream) -> Result<ProcessIdentity, OsError> {
    let token = peer_audit_token(stream)?;
    Ok(unsafe { ProcessIdentity::from_kernel_token(token) })
}

#[cfg(all(test, target_os = "linux"))]
mod linux_tests {
    use super::*;

    #[test]
    fn peer_audit_token_uses_so_peercred() {
        let (a, _b) = UnixStream::pair().expect("socket pair");

        let token = peer_audit_token(&a).expect("peer audit token");

        assert_eq!(token.val[5] as libc::pid_t, unsafe { libc::getpid() });
        assert_eq!(token.val[1], unsafe { libc::geteuid() });
        assert_eq!(token.val[2], unsafe { libc::getegid() });
        assert_ne!(token.val[7], 0, "linux starttime pidversion should be set");
    }
}

#[cfg(all(test, not(any(target_os = "macos", target_os = "linux"))))]
mod tests {
    use super::*;

    #[test]
    fn peer_audit_token_is_explicitly_unsupported() {
        let (a, _b) = UnixStream::pair().expect("socket pair");
        let err = peer_audit_token(&a).expect_err("non-macOS peer audit token");
        assert!(matches!(
            err,
            OsError::Unsupported {
                capability: "peer audit token",
                ..
            }
        ));
    }
}
