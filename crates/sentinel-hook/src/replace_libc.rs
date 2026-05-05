//! Seven replacement functions for the Phase 1 libc hook surface (D-08).
//!
//! Hot-path discipline (D-03): no heap allocation; bytewise hostname matching;
//! cache lookups against fixed-size storage; reentrancy-guard set/clear.

use crate::cache::{Cache, MAX_HOSTNAME, MAX_SOCKADDR_BYTES};
use crate::interpose::*;
use crate::log_buffer::LOG_RING;
use crate::reentrancy::IN_HOOK;
use crate::snapshot::FAIL_CLOSED;
use crate::ALLOWLIST;
use core::ffi::{c_char, c_int, c_void};
use core::sync::atomic::Ordering;
use libc::{addrinfo, msghdr, size_t, ssize_t, sockaddr, socklen_t};
use sentinel_core::{match_hostname, AllowlistEntry, Verdict};

// EAI_FAIL is -4 on macOS; we use libc constant.
const DENY_EAI: c_int = libc::EAI_FAIL;

// macOS syscall numbers for the five interposed symbols.
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

/// Extract hostname C-string into a stack buffer. Returns None if hostname is
/// null, oversized, or contains non-printable bytes.
fn hostname_bytes(node: *const c_char) -> Option<([u8; MAX_HOSTNAME], usize)> {
    if node.is_null() {
        return None;
    }
    let mut buf = [0u8; MAX_HOSTNAME];
    let mut n = 0usize;
    unsafe {
        loop {
            if n >= MAX_HOSTNAME {
                return None;
            }
            let b = *node.add(n) as u8;
            if b == 0 {
                break;
            }
            buf[n] = b;
            n += 1;
        }
    }
    Some((buf, n))
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
    // Reentrancy guard: if we're already inside a sentinel hook on this thread,
    // fall through to the real syscall immediately without re-evaluating policy.
    // This handles cases where the verdict logic itself calls connect internally.
    if IN_HOOK.with(|c| c.replace(true)) {
        return unsafe { raw_connect(s, addr, addrlen) };
    }
    let verdict = decide_for_sockaddr(addr, addrlen);
    IN_HOOK.with(|c| c.set(false));
    if matches!(verdict, Verdict::Deny) {
        unsafe { *libc::__error() = libc::EHOSTUNREACH; }
        LOG_RING.append(b"[sentinel-hook] DENY connect");
        return -1;
    }
    unsafe { raw_connect(s, addr, addrlen) }
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
    if IN_HOOK.with(|c| c.replace(true)) {
        let r = unsafe {
            libc::syscall(SYS_CONNECTX, s, endpoints, associd, flags, iov, iovcnt, len, connid) as c_int
        };
        return r;
    }

    let verdict = if endpoints.is_null() {
        Verdict::Deny
    } else {
        let ep = unsafe { &*(endpoints as *const SaEndpoints) };
        decide_for_sockaddr(ep.sae_dstaddr, ep.sae_dstaddrlen)
    };

    IN_HOOK.with(|c| c.set(false));
    if matches!(verdict, Verdict::Deny) {
        unsafe { *libc::__error() = libc::EHOSTUNREACH; }
        LOG_RING.append(b"[sentinel-hook] DENY connectx");
        return -1;
    }
    unsafe {
        libc::syscall(SYS_CONNECTX, s, endpoints, associd, flags, iov, iovcnt, len, connid) as c_int
    }
}

// ---- getaddrinfo ----

#[unsafe(no_mangle)]
unsafe extern "C" fn sentinel_getaddrinfo(
    node: *const c_char,
    service: *const c_char,
    hints: *const addrinfo,
    res: *mut *mut addrinfo,
) -> c_int {
    if IN_HOOK.with(|c| c.replace(true)) {
        let real = REAL_GETADDRINFO.load(Ordering::Relaxed);
        let r = if real.is_null() {
            DENY_EAI
        } else {
            let f: unsafe extern "C" fn(
                *const c_char,
                *const c_char,
                *const addrinfo,
                *mut *mut addrinfo,
            ) -> c_int = unsafe { core::mem::transmute(real) };
            unsafe { f(node, service, hints, res) }
        };
        return r;
    }
    let entries = match entries_or_deny() {
        Some(e) => e,
        None => {
            IN_HOOK.with(|c| c.set(false));
            LOG_RING.append(b"[sentinel-hook] DENY getaddrinfo (fail-closed)");
            return DENY_EAI;
        }
    };
    let host_match = match hostname_bytes(node) {
        Some((buf, n)) => match match_hostname(entries, &buf[..n]) {
            Verdict::Allow => Some((buf, n)),
            Verdict::Deny => {
                IN_HOOK.with(|c| c.set(false));
                LOG_RING.append(b"[sentinel-hook] DENY getaddrinfo");
                return DENY_EAI;
            }
        },
        None => None, // null hostname → numeric-only resolution; let it pass-through
    };
    // Allowed: call original.
    let real = REAL_GETADDRINFO.load(Ordering::Relaxed);
    let rc = if real.is_null() {
        DENY_EAI
    } else {
        let f: unsafe extern "C" fn(
            *const c_char,
            *const c_char,
            *const addrinfo,
            *mut *mut addrinfo,
        ) -> c_int = unsafe { core::mem::transmute(real) };
        unsafe { f(node, service, hints, res) }
    };
    // On success, populate cache for each returned addrinfo so connect() later
    // can recover the hostname.
    if rc == 0 {
        if let Some((host_buf, host_n)) = host_match {
            unsafe {
                let mut p = *res;
                while !p.is_null() {
                    let ai = &*p;
                    if !ai.ai_addr.is_null() && ai.ai_addrlen as usize <= MAX_SOCKADDR_BYTES {
                        let mut sb = [0u8; MAX_SOCKADDR_BYTES];
                        core::ptr::copy_nonoverlapping(
                            ai.ai_addr as *const u8,
                            sb.as_mut_ptr(),
                            ai.ai_addrlen as usize,
                        );
                        with_cache(|c| {
                            c.insert(&sb[..ai.ai_addrlen as usize], &host_buf[..host_n])
                        });
                    }
                    p = ai.ai_next;
                }
            }
        }
    }
    IN_HOOK.with(|c| c.set(false));
    rc
}

// ---- getaddrinfo_async / getaddrinfo_async_call ----
//
// NOTE: These symbols were planned per D-08 but are NOT present in macOS 26
// (Sequoia) SDK. Both `getaddrinfo_async` and `getaddrinfo_async_call` were
// deprecated in earlier macOS releases and have been removed from the dyld
// shared cache on macOS 26. Attempting to reference them as interpose targets
// causes an "Undefined symbols" linker error.
//
// [Rule 1 - Bug] Deviation from plan: reduced interpose set from 7 to 5 symbols.
// getaddrinfo_async and getaddrinfo_async_call are excluded. The REAL_GETADDRINFO_ASYNC
// and REAL_GETADDRINFO_ASYNC_CALL AtomicPtrs in interpose.rs remain (they get null
// from dlsym at ctor time, which is handled gracefully). The interpose section will
// be 5 × 16 = 80 bytes (0x50) instead of the planned 112 bytes (0x70).
// Plan 07 can add nw_* Network.framework interception to cover the gap.
// Tracked in SUMMARY deviations.

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
    if IN_HOOK.with(|c| c.replace(true)) {
        return unsafe { raw_sendto(s, buf, len, flags, to, tolen) };
    }
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
    IN_HOOK.with(|c| c.set(false));
    if matches!(verdict, Verdict::Deny) {
        unsafe { *libc::__error() = libc::EHOSTUNREACH; }
        LOG_RING.append(b"[sentinel-hook] DENY sendto");
        return -1;
    }
    unsafe { raw_sendto(s, buf, len, flags, to, tolen) }
}

// ---- sendmsg ----

#[unsafe(no_mangle)]
unsafe extern "C" fn sentinel_sendmsg(
    s: c_int,
    msg: *const msghdr,
    flags: c_int,
) -> ssize_t {
    if IN_HOOK.with(|c| c.replace(true)) {
        return unsafe { raw_sendmsg(s, msg, flags) };
    }
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
    IN_HOOK.with(|c| c.set(false));
    if matches!(verdict, Verdict::Deny) {
        unsafe { *libc::__error() = libc::EHOSTUNREACH; }
        LOG_RING.append(b"[sentinel-hook] DENY sendmsg");
        return -1;
    }
    unsafe { raw_sendmsg(s, msg, flags) }
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
        Some((buf, n)) => match_hostname(entries, &buf[..n]),
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
        match_hostname(entries, slice)
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
