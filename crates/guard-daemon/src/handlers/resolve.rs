//! Resolve handler.
//!
//! Daemon-side getaddrinfo proxy. v0.1 dropped the dylib's getaddrinfo
//! interpose because `DYLD_INSERT_LIBRARIES` patched `dlsym(RTLD_NEXT)` too,
//! creating infinite recursion. Daemon-side resolution uses the daemon's
//! own libc which is NOT under DYLD interpose — clean.

use guard_core::allowlist::AllowlistEntry;
use guard_ipc::{ResolveReply, SOCKADDR_WIRE_LEN};
use std::net::{SocketAddr, ToSocketAddrs};
use std::path::Path;
use tracing::{debug, warn};

pub fn handle_resolve(host: &str, port: u16) -> ResolveReply {
    let addr_str = format!("{host}:{port}");
    let resolved: Vec<SocketAddr> = match addr_str.to_socket_addrs() {
        Ok(iter) => iter.collect(),
        Err(e) => {
            warn!(host = %host, port, error = %e, "Resolve failed");
            return ResolveReply::err(format!("resolve {host}:{port}: {e}"));
        }
    };
    let mut wire: Vec<[u8; SOCKADDR_WIRE_LEN]> = Vec::with_capacity(resolved.len());
    for sa in resolved {
        wire.push(sockaddr_to_wire(&sa));
    }
    if wire.is_empty() {
        return ResolveReply::err(format!("resolve {host}:{port}: no addresses"));
    }
    debug!(host = %host, port, count = wire.len(), "Resolve OK");
    ResolveReply::addresses(wire)
}

/// Load a per-run snapshot from disk and return its entries. Returns None on
/// any I/O or decode error (caller falls through to unconditional resolve).
#[must_use]
pub fn load_run_entries(snapshot_path: &Path) -> Option<Vec<AllowlistEntry>> {
    let bytes = std::fs::read(snapshot_path).ok()?;
    let snap = guard_core::Snapshot::decode(&bytes).ok()?;
    Some(snap.entries)
}

/// Encode a `SocketAddr` into a 28-byte buffer (`sizeof(sockaddr_in6)` on Darwin).
/// Layout:
///   [0]    `sa_len`  (Darwin-specific length byte)
///   [1]    `sa_family` (`AF_INET=2` or `AF_INET6=30`)
///   [2..4] port (big-endian)
///   IPv4: [4..8] `sin_addr`; remaining bytes zero (`sin_zero`)
///   IPv6: [4..8] `sin6_flowinfo`; [8..24] `sin6_addr`; [24..28] `sin6_scope_id`
fn sockaddr_to_wire(sa: &SocketAddr) -> [u8; SOCKADDR_WIRE_LEN] {
    let mut buf = [0u8; SOCKADDR_WIRE_LEN];
    match sa {
        SocketAddr::V4(v4) => {
            buf[0] = 16; // sin_len = sizeof(sockaddr_in)
            buf[1] = u8::try_from(libc::AF_INET).unwrap_or_default();
            buf[2..4].copy_from_slice(&v4.port().to_be_bytes());
            buf[4..8].copy_from_slice(&v4.ip().octets());
            // remaining bytes (8..28) are zero (sin_zero/padding)
        }
        SocketAddr::V6(v6) => {
            buf[0] = 28; // sin6_len = sizeof(sockaddr_in6)
            buf[1] = u8::try_from(libc::AF_INET6).unwrap_or_default();
            buf[2..4].copy_from_slice(&v6.port().to_be_bytes());
            // bytes 4..8 = sin6_flowinfo (zero — caller can encode if needed)
            buf[8..24].copy_from_slice(&v6.ip().octets());
            // bytes 24..28 = sin6_scope_id (zero — caller can encode if needed)
        }
    }
    buf
}
