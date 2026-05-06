//! Seven replacement functions for the Phase 1 libc hook surface (D-08).
//!
//! Hot-path discipline (D-03): no heap allocation; bytewise hostname matching;
//! cache lookups against fixed-size storage; reentrancy-guard set/clear.

use crate::cache::{Cache, MAX_HOSTNAME, MAX_SOCKADDR_BYTES};
use crate::log_buffer::LOG_RING;
use crate::reentrancy::IN_HOOK;
use crate::snapshot::FAIL_CLOSED;
use crate::ALLOWLIST;
use core::ffi::{c_char, c_int, c_void};
use core::sync::atomic::Ordering;
use libc::{msghdr, size_t, ssize_t, sockaddr, socklen_t};
use sentinel_core::{evaluate_rule, AllowlistEntry, Verdict};

/// Phase-1 compatibility shim: walk a flat `entries` slice and return the
/// FIRST matching entry's verdict; Deny if no entry matches. Plan 02-02 will
/// replace callers of this with the tier-walk `evaluate_policy` evaluator.
#[inline]
fn match_hostname_compat(entries: &[AllowlistEntry], host: &[u8]) -> Verdict {
    for e in entries {
        if let Some(v) = evaluate_rule(e, host) {
            return v;
        }
    }
    Verdict::Deny
}

// BL-04 fix: RAII reentrancy guard.
//
// The previous pattern cleared IN_HOOK BEFORE dispatching the real syscall:
//   set_guard(); decide(); CLEAR_GUARD(); if deny { return -1; } real_call();
//
// That left the dispatch window completely unguarded — if any code path
// between the clear and the return re-entered a hook, IN_HOOK would be false
// and the hook would re-evaluate policy rather than passing through.
//
// The correct pattern is: guard is held for the entire function scope and
// drops AFTER the real dispatch. An RAII guard achieves this automatically:
//   let _g = InHookGuard::enter()?;  // set on entry
//   decide();
//   real_call();
//   // _g drops here, IN_HOOK cleared AFTER the real call returns
//
// InHookGuard::enter() returns None if already in a hook (pass-through path);
// returns Some(guard) that holds IN_HOOK=true until Drop.
struct InHookGuard {
    _priv: (),
}

impl InHookGuard {
    /// Try to enter the hook. Returns None if already in a hook on this
    /// thread (reentrancy detected — caller must pass through immediately).
    /// Returns Some(guard) when we successfully set IN_HOOK=true.
    #[inline]
    fn enter() -> Option<Self> {
        // replace(true) returns the OLD value. If old was true, we are
        // already in a hook → return None (caller takes the pass-through path).
        // If old was false, we are now the outermost hook frame → return guard.
        if IN_HOOK.with(|c| c.replace(true)) {
            None
        } else {
            Some(Self { _priv: () })
        }
    }
}

impl Drop for InHookGuard {
    #[inline]
    fn drop(&mut self) {
        IN_HOOK.with(|c| c.set(false));
    }
}

// macOS syscall numbers for the four interposed symbols.
// Using direct syscalls bypasses the __DATA,__interpose mechanism entirely,
// which is essential: when our dylib is injected via DYLD_INSERT_LIBRARIES,
// dyld patches ALL symbol lookups (including dlsym on the original image) to
// return our replacement functions. The only escape from the interpose chain
// is a raw syscall (the kernel entry point is never interposed).
//
// Verified from macOS 15.4 SDK /usr/include/sys/syscall.h:
//   SYS_sendmsg=28, SYS_connect=98, SYS_sendto=133, SYS_connectx=447
// These numbers are stable across macOS versions (BSD socket ABI).
const SYS_CONNECT: libc::c_int = 98;
const SYS_CONNECTX: libc::c_int = 447;
const SYS_SENDTO: libc::c_int = 133;
const SYS_SENDMSG: libc::c_int = 28;

/// Call the real kernel connect(2) by bypassing the libc stub entirely.
/// This avoids the infinite recursion caused by DYLD_INSERT_LIBRARIES
/// patching all symbol lookups to return sentinel_connect instead of libSystem's connect.
#[inline(always)]
unsafe fn raw_connect(s: c_int, addr: *const sockaddr, addrlen: socklen_t) -> c_int {
    unsafe { libc::syscall(SYS_CONNECT, s, addr, addrlen) as c_int }
}

/// Call the real kernel sendto(2) via raw syscall.
#[inline(always)]
unsafe fn raw_sendto(
    s: c_int,
    buf: *const c_void,
    len: size_t,
    flags: c_int,
    to: *const sockaddr,
    tolen: socklen_t,
) -> ssize_t {
    unsafe { libc::syscall(SYS_SENDTO, s, buf, len, flags, to, tolen) as ssize_t }
}

/// Call the real kernel sendmsg(2) via raw syscall.
#[inline(always)]
unsafe fn raw_sendmsg(s: c_int, msg: *const msghdr, flags: c_int) -> ssize_t {
    unsafe { libc::syscall(SYS_SENDMSG, s, msg, flags) as ssize_t }
}

// ISS-06 disposition: ENF-06 verification scope is documented as MATCHER-ONLY
// in Phase 1. The `with_cache` helper takes a process-global Mutex on every
// hot-path call (decide_for_sockaddr → cache.lookup), and `std::sync::Mutex`
// on macOS is a `pthread_mutex` that may heap-allocate on first lock and has
// unbounded contention behaviour. The criterion bench in benches/hot_path.rs
// exercises `match_hostname` ONLY — it does NOT load the cache + Mutex path,
// so the Phase 1 ENF-06 microbench is not load-bearing for the full hot-path
// budget. The formal benchmark on real hardware lands in Phase 5 (VAL-03).
//
// D-17 locks the cache as "per-process". A future Phase 5 polish can convert
// this to a `thread_local!` per-thread cache.
fn with_cache<R>(f: impl FnOnce(&mut Cache) -> R) -> R {
    use std::sync::Mutex;
    static GLOBAL: Mutex<Cache> = Mutex::new(Cache::new());
    let mut g = GLOBAL.lock().expect("getaddrinfo cache");
    f(&mut g)
}

fn entries_or_deny() -> Option<&'static [AllowlistEntry]> {
    if FAIL_CLOSED.load(Ordering::Acquire) {
        return None;
    }
    ALLOWLIST.get().map(|v| v.as_slice())
}

/// Sockaddr → opaque bytes for cache key. Includes full sockaddr length.
fn sockaddr_bytes(
    addr: *const sockaddr,
    addrlen: socklen_t,
) -> Option<([u8; MAX_SOCKADDR_BYTES], usize)> {
    if addr.is_null() {
        return None;
    }
    let len = addrlen as usize;
    if len == 0 || len > MAX_SOCKADDR_BYTES {
        return None;
    }
    let mut buf = [0u8; MAX_SOCKADDR_BYTES];
    unsafe {
        core::ptr::copy_nonoverlapping(addr as *const u8, buf.as_mut_ptr(), len);
    }
    Some((buf, len))
}

// ---- connect ----

#[unsafe(no_mangle)]
pub unsafe extern "C" fn sentinel_connect(
    s: c_int,
    addr: *const sockaddr,
    addrlen: socklen_t,
) -> c_int {
    // BL-04 fix: RAII guard — IN_HOOK is cleared when _guard drops, which
    // happens AFTER raw_connect returns (or after the early-return on deny).
    // The dispatch window is now correctly bracketed by the guard lifetime.
    let _guard = match InHookGuard::enter() {
        Some(g) => g,
        None => return unsafe { raw_connect(s, addr, addrlen) },
    };
    let verdict = decide_for_sockaddr(addr, addrlen);
    if matches!(verdict, Verdict::Deny) {
        unsafe { *libc::__error() = libc::EHOSTUNREACH; }
        LOG_RING.append(b"[sentinel-hook] DENY connect");
        return -1;
        // _guard drops here: IN_HOOK cleared after deny path
    }
    unsafe { raw_connect(s, addr, addrlen) }
    // _guard drops here: IN_HOOK cleared after real syscall returns
}

// ---- connectx (Darwin-specific) ----
//
// `connectx(2)` takes an `sa_endpoints_t` describing the source and destination
// endpoints. ISS-09 remediation: extract the destination sockaddr (sae_dstaddr)
// and route it through the same `decide_for_sockaddr` path as `connect`. D-08
// locks connectx in Phase 1.
//
// `sa_endpoints_t` layout from `<sys/socket.h>` (Darwin):
//     typedef struct sa_endpoints {
//         unsigned int      sae_srcif;       // optional source interface
//         const struct sockaddr *sae_srcaddr; // optional source address
//         socklen_t         sae_srcaddrlen;
//         const struct sockaddr *sae_dstaddr; // destination — what we filter on
//         socklen_t         sae_dstaddrlen;
//     } sa_endpoints_t;

#[repr(C)]
struct SaEndpoints {
    sae_srcif: u32,
    sae_srcaddr: *const sockaddr,
    sae_srcaddrlen: socklen_t,
    sae_dstaddr: *const sockaddr,
    sae_dstaddrlen: socklen_t,
}

#[unsafe(no_mangle)]
unsafe extern "C" fn sentinel_connectx(
    s: c_int,
    endpoints: *const c_void, // sa_endpoints_t *
    associd: c_int,
    flags: u32,
    iov: *const c_void,    // iovec *
    iovcnt: c_int,
    len: *mut size_t,
    connid: *mut c_int, // connid_t *
) -> c_int {
    // BL-04 fix: RAII guard — IN_HOOK cleared after dispatch, not before.
    let _guard = match InHookGuard::enter() {
        Some(g) => g,
        None => return unsafe {
            libc::syscall(SYS_CONNECTX, s, endpoints, associd, flags, iov, iovcnt, len, connid) as c_int
        },
    };

    let verdict = if endpoints.is_null() {
        Verdict::Deny
    } else {
        let ep = unsafe { &*(endpoints as *const SaEndpoints) };
        decide_for_sockaddr(ep.sae_dstaddr, ep.sae_dstaddrlen)
    };

    if matches!(verdict, Verdict::Deny) {
        unsafe { *libc::__error() = libc::EHOSTUNREACH; }
        LOG_RING.append(b"[sentinel-hook] DENY connectx");
        return -1;
        // _guard drops here: IN_HOOK cleared after deny
    }
    unsafe {
        libc::syscall(SYS_CONNECTX, s, endpoints, associd, flags, iov, iovcnt, len, connid) as c_int
    }
    // _guard drops here: IN_HOOK cleared after real syscall returns
}

// ---- getaddrinfo ----
//
// BL-05 fix: sentinel_getaddrinfo DELETED.
//
// getaddrinfo was removed from the __DATA,__interpose table in plan 01-09
// (see deviation comment below at the interpose records section) because
// DYLD_INSERT_LIBRARIES patches ALL symbol-table entries globally — including
// those within libSystem — so REAL_GETADDRINFO ended up pointing back to
// sentinel_getaddrinfo, causing infinite recursion on the allow path.
//
// Despite being removed from the interpose table, sentinel_getaddrinfo
// remained defined with #[unsafe(no_mangle)], making it a globally-visible
// exported C symbol. This was a foot-gun: the symbol was dead (never called
// via dyld interpose) but exported, misleading future contributors.
//
// Fix: delete the function entirely. The REAL_GETADDRINFO AtomicPtr in
// interpose.rs is retained (it gets the real getaddrinfo from dlsym at init
// time, which is harmless — it's just never consulted on the hot path).
//
// getaddrinfo_async and getaddrinfo_async_call are also excluded (removed
// from macOS 26 SDK). Tracked in SUMMARY deviations.
//
// [Rule 1 - Bug] Original deviation from plan: reduced interpose set from 7
// to 5 symbols. Plan 07 adds nw_* Network.framework interception.

// ---- sendto ----

#[unsafe(no_mangle)]
unsafe extern "C" fn sentinel_sendto(
    s: c_int,
    buf: *const c_void,
    len: size_t,
    flags: c_int,
    to: *const sockaddr,
    tolen: socklen_t,
) -> ssize_t {
    // BL-04 fix: RAII guard — IN_HOOK cleared after dispatch, not before.
    let _guard = match InHookGuard::enter() {
        Some(g) => g,
        None => return unsafe { raw_sendto(s, buf, len, flags, to, tolen) },
    };
    // Phase 1 policy for sendto:
    // - to null or tolen=0 → Allow (connected socket send; the destination
    //   address was already permitted at connect() time). Denying connected
    //   sends would break all established TCP data flows.
    // - to set → run the allowlist check.
    let verdict = if to.is_null() || tolen == 0 {
        Verdict::Allow
    } else {
        decide_for_sockaddr(to, tolen)
    };
    if matches!(verdict, Verdict::Deny) {
        unsafe { *libc::__error() = libc::EHOSTUNREACH; }
        LOG_RING.append(b"[sentinel-hook] DENY sendto");
        return -1;
        // _guard drops here: IN_HOOK cleared after deny
    }
    unsafe { raw_sendto(s, buf, len, flags, to, tolen) }
    // _guard drops here: IN_HOOK cleared after real syscall returns
}

// ---- sendmsg ----

#[unsafe(no_mangle)]
unsafe extern "C" fn sentinel_sendmsg(
    s: c_int,
    msg: *const msghdr,
    flags: c_int,
) -> ssize_t {
    // BL-04 fix: RAII guard — IN_HOOK cleared after dispatch, not before.
    let _guard = match InHookGuard::enter() {
        Some(g) => g,
        None => return unsafe { raw_sendmsg(s, msg, flags) },
    };
    // Phase 1 policy for sendmsg:
    // - null msg → Deny (invalid call).
    // - msg_name null or msg_namelen=0 → Allow (connected socket send; no
    //   destination address means the kernel uses the connected address,
    //   which was already permitted at connect() time). Blocking connected
    //   sends would break all established TCP/Unix socket data flows.
    // - msg_name set → run the same allowlist check as connect().
    let verdict = if msg.is_null() {
        Verdict::Deny
    } else {
        let m = unsafe { &*msg };
        if m.msg_name.is_null() || m.msg_namelen == 0 {
            Verdict::Allow
        } else {
            decide_for_sockaddr(m.msg_name as *const sockaddr, m.msg_namelen)
        }
    };
    if matches!(verdict, Verdict::Deny) {
        unsafe { *libc::__error() = libc::EHOSTUNREACH; }
        LOG_RING.append(b"[sentinel-hook] DENY sendmsg");
        return -1;
        // _guard drops here: IN_HOOK cleared after deny
    }
    unsafe { raw_sendmsg(s, msg, flags) }
    // _guard drops here: IN_HOOK cleared after real syscall returns
}

// ---- shared decision path for connect/sendto/sendmsg ----

fn decide_for_sockaddr(addr: *const sockaddr, addrlen: socklen_t) -> Verdict {
    // Phase 1 policy: Unix domain sockets (AF_UNIX) are always allowed.
    // They are local IPC — not network egress. Denying them breaks Node's
    // internal libuv event loop (it uses a Unix socketpair for signaling),
    // the daemon's own socket, and any other local IPC. (Rule 1 auto-fix.)
    if !addr.is_null()
        && addrlen as usize >= core::mem::size_of::<libc::sa_family_t>()
    {
        let family = unsafe { (*addr).sa_family };
        if family as i32 == libc::AF_UNIX {
            return Verdict::Allow;
        }
    }

    let entries = match entries_or_deny() {
        Some(e) => e,
        None => return Verdict::Deny,
    };
    let (sa_buf, sa_n) = match sockaddr_bytes(addr, addrlen) {
        Some(v) => v,
        None => return Verdict::Deny,
    };
    // Look up in cache for hostname.
    let host = with_cache(|c| {
        // Copy the hostname out of the cache to avoid holding the lock across match_hostname.
        c.lookup(&sa_buf[..sa_n]).map(|h| {
            let mut buf = [0u8; MAX_HOSTNAME];
            buf[..h.len()].copy_from_slice(h);
            (buf, h.len())
        })
    });
    match host {
        Some((buf, n)) => match_hostname_compat(entries, &buf[..n]),
        None => {
            // No prior getaddrinfo for this sockaddr → could be hardcoded-IP egress.
            // D-17: deny by default within tracked subtrees.
            // Phase 1: if the sockaddr is an IPv4/IPv6 address that ALSO appears as
            // an Ip(_) entry in the allowlist (e.g. 127.0.0.1), allow it.
            decide_for_ip_sockaddr(addr, addrlen, entries)
        }
    }
}

fn decide_for_ip_sockaddr(
    addr: *const sockaddr,
    addrlen: socklen_t,
    entries: &[AllowlistEntry],
) -> Verdict {
    if addr.is_null() {
        return Verdict::Deny;
    }
    let mut buf = [0u8; 64];
    let s = unsafe { ip_to_str(addr, addrlen, &mut buf) };
    if let Some(slice) = s {
        match_hostname_compat(entries, slice)
    } else {
        Verdict::Deny
    }
}

// libc crate does not export inet_ntop on all versions; declare it directly.
unsafe extern "C" {
    fn inet_ntop(af: c_int, src: *const c_void, dst: *mut c_char, size: socklen_t)
        -> *const c_char;
}

unsafe fn ip_to_str<'a>(
    addr: *const sockaddr,
    addrlen: socklen_t,
    buf: &'a mut [u8; 64],
) -> Option<&'a [u8]> {
    if addrlen as usize >= core::mem::size_of::<libc::sa_family_t>() {
        let family = unsafe { (*addr).sa_family };
        match family as i32 {
            libc::AF_INET => {
                if addrlen as usize >= core::mem::size_of::<libc::sockaddr_in>() {
                    let sin = unsafe { &*(addr as *const libc::sockaddr_in) };
                    let r = unsafe {
                        inet_ntop(
                            libc::AF_INET,
                            &sin.sin_addr as *const _ as *const c_void,
                            buf.as_mut_ptr() as *mut c_char,
                            buf.len() as socklen_t,
                        )
                    };
                    if !r.is_null() {
                        let mut n = 0usize;
                        while n < buf.len() && buf[n] != 0 {
                            n += 1;
                        }
                        return Some(&buf[..n]);
                    }
                }
            }
            libc::AF_INET6 => {
                if addrlen as usize >= core::mem::size_of::<libc::sockaddr_in6>() {
                    let sin6 = unsafe { &*(addr as *const libc::sockaddr_in6) };
                    let r = unsafe {
                        inet_ntop(
                            libc::AF_INET6,
                            &sin6.sin6_addr as *const _ as *const c_void,
                            buf.as_mut_ptr() as *mut c_char,
                            buf.len() as socklen_t,
                        )
                    };
                    if !r.is_null() {
                        let mut n = 0usize;
                        while n < buf.len() && buf[n] != 0 {
                            n += 1;
                        }
                        return Some(&buf[..n]);
                    }
                }
            }
            _ => {}
        }
    }
    None
}

// ---- THE INTERPOSE RECORDS ----
// These MUST live in the SAME translation unit as the function bodies (or be
// referenced from one); we emit them here.
//
// ISS-02 remediation: `unsafe extern "C"` blocks are NOT permitted inside
// `static` initializers. Declare each non-libc-exposed real symbol at MODULE
// scope, then reference the function name directly inside the interpose pair.
// libc 0.2.x does NOT expose connectx, getaddrinfo_async, or
// getaddrinfo_async_call as Rust items; we declare them ourselves here.
//
// `connect`, `getaddrinfo`, `sendto`, `sendmsg` ARE exposed by libc 0.2.x and
// can be referenced via `libc::<name> as *const c_void` directly.
//
// Note: raw function pointers are not Sync in Rust 2024 strict mode.
// We wrap them in SyncPtr to explicitly opt-in to Sync. The __interpose section
// is a read-only data structure consumed by dyld at load time; it is never
// written after the linker places it, so Sync is sound here.

#[allow(dead_code)]
struct SyncPtr(*const c_void);
unsafe impl Sync for SyncPtr {}

unsafe extern "C" {
    fn connectx(
        s: c_int,
        endpoints: *const c_void,
        associd: c_int,
        flags: u32,
        iov: *const c_void,
        iovcnt: c_int,
        len: *mut size_t,
        connid: *mut c_int,
    ) -> c_int;
}

// Phase 1 interpose records: connect, connectx, sendto, sendmsg.
//
// DEVIATION from plan (getaddrinfo removed, Rule 1 - Bug):
// getaddrinfo is NOT interposed in Phase 1. Root cause: when libsentinel_hook.dylib
// is injected via DYLD_INSERT_LIBRARIES, dyld patches ALL symbol table entries
// globally — including those within libSystem itself. This means dlsym(libSystem,
// "getaddrinfo") and RTLD_NEXT both return sentinel_getaddrinfo's address. There is
// no way to call the real getaddrinfo from within the interposing dylib without a raw
// syscall, and getaddrinfo is NOT a simple syscall (it goes through mDNSResponder
// via XPC). Using IN_HOOK as a reentrancy guard in the allow path leads to
// sentinel_getaddrinfo calling itself infinitely via REAL_GETADDRINFO.
//
// Phase 1 enforcement strategy without getaddrinfo interception:
// - DENY path: discord.com and other non-allowlisted hosts are denied at connect(2)
//   level, AFTER DNS resolution. The IP address returned by getaddrinfo is not in
//   the D-18 allowlist (which only has 127.0.0.1, ::1, registry.npmjs.org etc.),
//   so decide_for_ip_sockaddr() returns Deny. Node sees EHOSTUNREACH.
// - ALLOW path: loopback (127.0.0.1, ::1) connects work because decide_for_ip_sockaddr
//   matches the Ip() entries in the allowlist.
// - Cache-based hostname matching (getaddrinfo → cache → connect) is NOT available in
//   Phase 1 since getaddrinfo isn't intercepted. Phase 5 will add a safer getaddrinfo
//   interception mechanism (e.g., using mach port messaging or a forked resolver).
//
// (getaddrinfo_async and getaddrinfo_async_call are also excluded — removed from macOS 26 SDK.)

#[unsafe(no_mangle)]
#[unsafe(link_section = "__DATA,__interpose")]
#[used]
static SENTINEL_INTERPOSE_CONNECT: [SyncPtr; 2] = [
    SyncPtr(sentinel_connect as *const c_void),
    SyncPtr(libc::connect as *const c_void),
];

#[unsafe(no_mangle)]
#[unsafe(link_section = "__DATA,__interpose")]
#[used]
static SENTINEL_INTERPOSE_CONNECTX: [SyncPtr; 2] = [
    SyncPtr(sentinel_connectx as *const c_void),
    SyncPtr(connectx as *const c_void),
];

#[unsafe(no_mangle)]
#[unsafe(link_section = "__DATA,__interpose")]
#[used]
static SENTINEL_INTERPOSE_SENDTO: [SyncPtr; 2] = [
    SyncPtr(sentinel_sendto as *const c_void),
    SyncPtr(libc::sendto as *const c_void),
];

#[unsafe(no_mangle)]
#[unsafe(link_section = "__DATA,__interpose")]
#[used]
static SENTINEL_INTERPOSE_SENDMSG: [SyncPtr; 2] = [
    SyncPtr(sentinel_sendmsg as *const c_void),
    SyncPtr(libc::sendmsg as *const c_void),
];
