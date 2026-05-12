//! Seven replacement functions for the Phase 1 libc hook surface (D-08).
//!
//! Hot-path discipline (D-03): no heap allocation; bytewise hostname matching;
//! cache lookups against fixed-size storage; reentrancy-guard set/clear.

use crate::cache::{Cache, MAX_HOSTNAME, MAX_SOCKADDR_BYTES};
use crate::ipc_client::{daemon_socket_path, send_deny_notify, send_resolve_sync};
use crate::log_buffer::LOG_RING;
use crate::reentrancy::IN_HOOK;
use crate::snapshot::FAIL_CLOSED;
use crate::ALLOWLIST;
use core::ffi::{c_char, c_int, c_void, CStr};
use crate::ipc_client::IpcClientError;
use core::sync::atomic::Ordering;
use libc::{msghdr, size_t, ssize_t, sockaddr, socklen_t, AF_INET, AF_INET6};
use sentinel_core::{
    allowlist::{MatchType, RuleKind, RuleTier},
    policy::{evaluate_policy, is_cloud_metadata_ip, is_loopback_ip},
    AllowlistEntry, Verdict,
};
use sentinel_ipc::{AuditTokenWire, SOCKADDR_WIRE_LEN};

/// Maximum number of Resolve-IPC round-trips per connect() invocation.
/// Bounds worst-case latency at MAX_RESOLVE_ATTEMPTS * RESOLVE_TIMEOUT_MS = 400ms.
/// gap-closure 02-08: bounds Resolve-IPC slow-loris DoS budget (T-02-08-02).
const MAX_RESOLVE_ATTEMPTS: usize = 4;

/// Per-Resolve-IPC timeout in milliseconds. One-time cost per (host, port) pair;
/// subsequent connects to the same sockaddr are cache-hit-only (sub-100µs).
/// This deviates from the CLAUDE.md <100µs per-intercepted-call budget for
/// the cache-miss warm-up path — documented in plan 02-08's threat model (T-02-08-02).
const RESOLVE_TIMEOUT_MS: u64 = 100;

/// BLOCKER-01 fix (Phase 2 review): the libc hot path now delegates to the
/// V2 tier-walk evaluator (`sentinel_core::policy::evaluate_policy`) — the
/// SAME chokepoint used by `replace_nw.rs::decide_for_nw_connection`.
///
/// This closes the BLOCKER-01 finding: the cloud-metadata hard rule (D-25b)
/// for `169.254.169.254` / `fe80::a9fe:a9fe`, the raw-IP cache-miss hard rule
/// (D-25c / ALLOW-08), AND the loopback hard rule (D-25a) are now ALL
/// enforced on the libc connect/sendto/sendmsg/connectx path — even when a
/// `.sentinel.toml` ProjectAllow entry tries to allow IMDS. The tier-walk
/// also produces correct `SourceKind` attribution for the daemon's block-log
/// (Phase 3 surfacing).
///
/// Inputs:
///   - `host`: the cache-resolved hostname bytes, OR empty if connect-by-IP
///   - `ip`: ASCII rendering of the destination IP, OR None
///   - `resolved_via_getaddrinfo`: true if we found this destination in the
///     dylib's per-process getaddrinfo cache (i.e. some prior code path
///     resolved it through getaddrinfo). False if connect happened with a
///     hardcoded numeric address with no prior resolution.
#[inline]
fn evaluate_in_hook(
    host: &[u8],
    ip: Option<&[u8]>,
    resolved_via_getaddrinfo: bool,
    entries: &[AllowlistEntry],
) -> Verdict {
    let (verdict, _src) = evaluate_policy(host, ip, resolved_via_getaddrinfo, entries);
    verdict
}

// BL-04 RAII reentrancy guard. See `reentrancy.rs` for the canonical
// rationale (WARNING-02 fix moved the long explanation there). Each hook
// file (`replace_fork.rs`, `replace_exec.rs`, etc.) carries a copy of the
// same struct; if you change one, change them all.
struct InHookGuard {
    _priv: (),
}

impl InHookGuard {
    /// Try to enter the hook. Returns None if already in a hook on this
    /// thread (reentrancy detected — caller must pass through immediately).
    /// Returns Some(guard) when we successfully set IN_HOOK=true.
    #[inline]
    fn enter() -> Option<Self> {
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

use crate::raw_syscall;

#[inline(always)]
unsafe fn raw_connect(s: c_int, addr: *const sockaddr, addrlen: socklen_t) -> c_int {
    unsafe { raw_syscall::raw_connect(s, addr, addrlen) }
}

#[inline(always)]
unsafe fn raw_sendto(
    s: c_int,
    buf: *const c_void,
    len: size_t,
    flags: c_int,
    to: *const sockaddr,
    tolen: socklen_t,
) -> ssize_t {
    unsafe { raw_syscall::raw_sendto(s, buf, len, flags, to, tolen) }
}

#[inline(always)]
unsafe fn raw_sendmsg(s: c_int, msg: *const msghdr, flags: c_int) -> ssize_t {
    unsafe { raw_syscall::raw_sendmsg(s, msg, flags) }
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
    // BL-04: RAII guard — IN_HOOK cleared when _guard drops (see
    // reentrancy.rs for the canonical rationale).
    let _guard = match InHookGuard::enter() {
        Some(g) => g,
        None => return unsafe { raw_connect(s, addr, addrlen) },
    };
    let verdict = decide_for_sockaddr(addr, addrlen);
    if matches!(verdict, Verdict::Deny) {
        LOG_RING.append(b"[sentinel-hook] DENY connect");
        unsafe { notify_deny_for_sockaddr(addr, addrlen, "connect") };
        unsafe { *libc::__error() = libc::EHOSTUNREACH; }
        return -1;
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
pub struct SaEndpoints {
    pub sae_srcif: u32,
    pub sae_srcaddr: *const sockaddr,
    pub sae_srcaddrlen: socklen_t,
    pub sae_dstaddr: *const sockaddr,
    pub sae_dstaddrlen: socklen_t,
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
    // BL-04: RAII guard — see reentrancy.rs for the canonical rationale.
    let _guard = match InHookGuard::enter() {
        Some(g) => g,
        None => return unsafe {
            raw_syscall::raw_connectx(s, endpoints, associd, flags, iov, iovcnt, len, connid)
        },
    };

    let verdict = if endpoints.is_null() {
        Verdict::Deny
    } else {
        let ep = unsafe { &*(endpoints as *const SaEndpoints) };
        decide_for_sockaddr(ep.sae_dstaddr, ep.sae_dstaddrlen)
    };

    if matches!(verdict, Verdict::Deny) {
        LOG_RING.append(b"[sentinel-hook] DENY connectx");
        if !endpoints.is_null() {
            let ep = unsafe { &*(endpoints as *const SaEndpoints) };
            unsafe { notify_deny_for_sockaddr(ep.sae_dstaddr, ep.sae_dstaddrlen, "connectx") };
        }
        unsafe { *libc::__error() = libc::EHOSTUNREACH; }
        return -1;
    }
    unsafe {
        raw_syscall::raw_connectx(s, endpoints, associd, flags, iov, iovcnt, len, connid)
    }
    // _guard drops here: IN_HOOK cleared after real syscall returns
}

// ---- getaddrinfo ----
//
// M005-S01: getaddrinfo interpose re-enabled with daemon-proxied DNS.
//
// BL-05 root cause was calling real getaddrinfo from the hook — DYLD patches
// it globally, so REAL_GETADDRINFO pointed back to sentinel_getaddrinfo
// (infinite recursion). The fix: DON'T call real getaddrinfo at all. Instead,
// proxy DNS through the daemon via Resolve IPC (tag 0x06). The daemon's
// getaddrinfo is NOT interposed (the daemon binary isn't loaded via
// DYLD_INSERT_LIBRARIES), so it resolves cleanly.
//
// Flow:
//   hooked process calls getaddrinfo("evil.com", "443", ...)
//   → sentinel_getaddrinfo intercepts
//   → sends Resolve { host, port } to daemon via Unix socket IPC
//   → daemon resolves DNS with its own libc, checks policy (M005-S02)
//   → hook receives ResolveReply::Addresses or ResolveReply::Deny
//   → on Addresses: populates DNS cache, assembles addrinfo linked list
//   → subsequent connect() to those IPs cache-hits → allowed
//
// Reentrancy safety: IPC uses AF_UNIX connect which passes through
// sentinel_connect's AF_UNIX fast-path (no policy check, no IPC).
// The InHookGuard also prevents re-entering sentinel_getaddrinfo if
// the IPC somehow triggers another getaddrinfo (it shouldn't — Unix
// sockets don't need DNS).

/// Timeout for daemon-proxied DNS resolution (milliseconds).
/// Generous to allow for prompted calls in M005-S02 (user reading/deciding).
/// Non-prompted calls complete in <10ms; prompted calls may take up to 30s.
const GETADDRINFO_RESOLVE_TIMEOUT_MS: u64 = 30_000;

#[unsafe(no_mangle)]
pub unsafe extern "C" fn sentinel_getaddrinfo(
    node: *const c_char,
    service: *const c_char,
    hints: *const libc::addrinfo,
    res: *mut *mut libc::addrinfo,
) -> c_int {
    let _guard = match InHookGuard::enter() {
        Some(g) => g,
        None => {
            // Reentrancy: should not happen (IPC uses AF_UNIX, not DNS), but
            // if it does, return EAI_AGAIN to signal transient failure.
            return libc::EAI_AGAIN;
        }
    };

    // Null output pointer: undefined behavior in POSIX, but be defensive.
    if res.is_null() {
        return libc::EAI_FAIL;
    }
    unsafe { *res = core::ptr::null_mut() };

    // Fail-closed: if the snapshot failed to load, deny all DNS resolution
    // so getaddrinfo is consistent with connect()'s deny path.
    if FAIL_CLOSED.load(Ordering::Acquire) {
        return libc::EAI_FAIL;
    }

    // No daemon socket → can't proxy DNS. Return EAI_AGAIN so callers that
    // retry (like curl) get a chance, or fall back to connect-by-IP which
    // hits the existing cache-miss-deny path.
    if daemon_socket_path().is_none() {
        return libc::EAI_AGAIN;
    }

    // Extract hostname. Null node with AI_PASSIVE means wildcard (bind use
    // case) — not relevant for outbound resolution, but pass it through.
    let hostname = if node.is_null() {
        None
    } else {
        let cstr = unsafe { CStr::from_ptr(node) };
        cstr.to_str().ok()
    };

    // If no hostname, this is a numeric/wildcard lookup. We can't proxy
    // meaningfully (the daemon resolves hostnames, not numeric addresses).
    // Return EAI_AGAIN — the caller typically has the IP already.
    let host = match hostname {
        Some(h) if !h.is_empty() => h,
        _ => return libc::EAI_AGAIN,
    };

    // Extract port from the service parameter. getaddrinfo accepts either
    // a numeric port string or a service name ("http", "https"). We only
    // handle numeric ports; for service names, pass port=0 and let the
    // daemon resolve without port constraint.
    let port: u16 = if service.is_null() {
        0
    } else {
        let svc = unsafe { CStr::from_ptr(service) };
        svc.to_str()
            .ok()
            .and_then(|s| s.parse::<u16>().ok())
            .unwrap_or(0)
    };

    // Send Resolve IPC to daemon.
    let addrs = match send_resolve_sync(host, port, GETADDRINFO_RESOLVE_TIMEOUT_MS) {
        Ok(a) if !a.is_empty() => a,
        Ok(_) => return libc::EAI_NONAME,
        Err(IpcClientError::NotConfigured) => return libc::EAI_AGAIN,
        Err(IpcClientError::Timeout) => return libc::EAI_AGAIN,
        Err(IpcClientError::DaemonRejected(ref reason)) => {
            // DaemonRejected covers both ResolveReply::Deny and
            // ResolveReply::Err. For Deny (policy block), EAI_FAIL is
            // correct — non-recoverable. For Err (DNS failure), EAI_NONAME.
            if reason.starts_with("resolve ") {
                return libc::EAI_NONAME;
            }
            return libc::EAI_FAIL;
        }
        Err(_) => return libc::EAI_FAIL,
    };

    // Extract hint preferences for the result nodes.
    let (hint_family, hint_socktype, hint_protocol) = if hints.is_null() {
        (0i32, 0i32, 0i32)
    } else {
        let h = unsafe { &*hints };
        (h.ai_family, h.ai_socktype, h.ai_protocol)
    };

    // Build the addrinfo linked list from wire addresses.
    // Each node is a single malloc allocation containing the addrinfo struct
    // followed by the sockaddr. sentinel_freeaddrinfo walks and frees them.
    let mut head: *mut libc::addrinfo = core::ptr::null_mut();
    let mut tail: *mut libc::addrinfo = core::ptr::null_mut();

    for wire in &addrs {
        // wire layout: [0]=sa_len, [1]=sa_family, [2..4]=port, rest=addr
        let sa_family = wire[1] as i32;
        let sa_len = wire[0] as usize;

        // Respect hint_family filter.
        if hint_family != 0 && hint_family != sa_family {
            continue;
        }

        // Determine sockaddr size for this address family.
        let sockaddr_size = match sa_family {
            AF_INET => core::mem::size_of::<libc::sockaddr_in>(),
            AF_INET6 => core::mem::size_of::<libc::sockaddr_in6>(),
            _ => continue,
        };

        // Populate the DNS cache with this address → hostname mapping.
        // The cache key is the raw sockaddr bytes (sa_len bytes of the wire).
        let cache_key_len = sa_len.min(SOCKADDR_WIRE_LEN);
        with_cache(|c| c.insert(&wire[..cache_key_len], host.as_bytes()));

        // Allocate addrinfo + embedded sockaddr in a single block.
        let ai_size = core::mem::size_of::<libc::addrinfo>();
        let total_size = ai_size + sockaddr_size;
        let ptr = unsafe { libc::malloc(total_size) } as *mut u8;
        if ptr.is_null() {
            // OOM: free what we've built so far and return EAI_MEMORY.
            unsafe { free_addrinfo_chain(head) };
            return libc::EAI_MEMORY;
        }
        unsafe { core::ptr::write_bytes(ptr, 0, total_size) };

        let ai_ptr = ptr as *mut libc::addrinfo;
        let sa_ptr = unsafe { ptr.add(ai_size) } as *mut libc::sockaddr;

        // Copy wire bytes into the sockaddr.
        let copy_len = sockaddr_size.min(SOCKADDR_WIRE_LEN);
        unsafe { core::ptr::copy_nonoverlapping(wire.as_ptr(), sa_ptr as *mut u8, copy_len) };

        // Fill the addrinfo fields.
        unsafe {
            (*ai_ptr).ai_family = sa_family;
            (*ai_ptr).ai_socktype = if hint_socktype != 0 { hint_socktype } else { libc::SOCK_STREAM };
            (*ai_ptr).ai_protocol = if hint_protocol != 0 { hint_protocol } else { libc::IPPROTO_TCP };
            (*ai_ptr).ai_addrlen = sockaddr_size as socklen_t;
            (*ai_ptr).ai_addr = sa_ptr;
            (*ai_ptr).ai_canonname = core::ptr::null_mut();
            (*ai_ptr).ai_next = core::ptr::null_mut();
        }

        // Append to the linked list.
        if head.is_null() {
            head = ai_ptr;
            tail = ai_ptr;
        } else {
            unsafe { (*tail).ai_next = ai_ptr };
            tail = ai_ptr;
        }
    }

    if head.is_null() {
        return libc::EAI_NONAME;
    }

    unsafe { *res = head };
    LOG_RING.append(b"[sentinel-hook] getaddrinfo proxied via daemon");
    0
}

/// Free an addrinfo linked list allocated by sentinel_getaddrinfo.
/// Each node was allocated as a single malloc block (addrinfo + sockaddr),
/// so a single free per node suffices.
unsafe fn free_addrinfo_chain(mut p: *mut libc::addrinfo) {
    while !p.is_null() {
        let next = unsafe { (*p).ai_next };
        unsafe { libc::free(p as *mut c_void) };
        p = next;
    }
}

/// Interposed freeaddrinfo — frees addrinfo lists from both
/// sentinel_getaddrinfo (our malloc'd nodes) and real getaddrinfo (system
/// nodes). Since we never call real getaddrinfo, all lists come from us
/// and are safe to free with our chain walker.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sentinel_freeaddrinfo(res: *mut libc::addrinfo) {
    unsafe { free_addrinfo_chain(res) };
}


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
    // BL-04: RAII guard — see reentrancy.rs for the canonical rationale.
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
        LOG_RING.append(b"[sentinel-hook] DENY sendto");
        unsafe { notify_deny_for_sockaddr(to, tolen, "sendto") };
        unsafe { *libc::__error() = libc::EHOSTUNREACH; }
        return -1;
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
    // BL-04: RAII guard — see reentrancy.rs for the canonical rationale.
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
        if !msg.is_null() {
            let m = unsafe { &*msg };
            if !m.msg_name.is_null() && m.msg_namelen > 0 {
                unsafe {
                    notify_deny_for_sockaddr(
                        m.msg_name as *const sockaddr,
                        m.msg_namelen,
                        "sendmsg",
                    );
                }
            }
        }
        return -1;
    }
    unsafe { raw_sendmsg(s, msg, flags) }
    // _guard drops here: IN_HOOK cleared after real syscall returns
}

// ---- shared decision path for connect/sendto/sendmsg ----

/// Public re-export for test-seam use from lib.rs's _test_decide_for_sockaddr.
/// `_` prefix signals test-seam convention.
///
/// # Safety
/// Same as `decide_for_sockaddr` — `addr` must be null or point to a valid sockaddr.
pub unsafe fn _decide_for_sockaddr_pub(addr: *const sockaddr, addrlen: socklen_t) -> Verdict {
    decide_for_sockaddr(addr, addrlen)
}

/// D-39: fire-and-forget deny notification to the daemon for forensic logging.
/// Extracts dest_host (from getaddrinfo cache), dest_ip, and dest_port from
/// the sockaddr and sends a DenyNotify IPC with a 50ms timeout.
///
/// # Safety
/// `addr` must be null or point to a valid sockaddr of at least `addrlen` bytes.
unsafe fn notify_deny_for_sockaddr(
    addr: *const sockaddr,
    addrlen: socklen_t,
    source_surface: &str,
) {
    if daemon_socket_path().is_none() {
        return;
    }

    let pid = unsafe { libc::getpid() } as u32;
    let ppid = unsafe { libc::getppid() } as u32;
    let mut token_val = [0u32; 8];
    token_val[5] = pid;
    token_val[6] = ppid;
    let audit_token = AuditTokenWire { val: token_val };

    let mut ip_buf = [0u8; 64];
    let ip_str = unsafe { ip_to_str(addr, addrlen, &mut ip_buf) };
    let ip_opt = ip_str.and_then(|b| core::str::from_utf8(b).ok());

    let port = if !addr.is_null() && addrlen as usize >= 4 {
        let sa_bytes = addr as *const u8;
        u16::from_be_bytes(unsafe { [*sa_bytes.add(2), *sa_bytes.add(3)] })
    } else {
        0
    };

    let (sa_buf, sa_n) = match sockaddr_bytes(addr, addrlen) {
        Some(v) => v,
        None => {
            send_deny_notify(audit_token, None, port, ip_opt, source_surface);
            return;
        }
    };
    let host_opt = with_cache(|c| {
        c.lookup(&sa_buf[..sa_n]).map(|h| {
            let mut buf = [0u8; MAX_HOSTNAME];
            let len = h.len().min(MAX_HOSTNAME);
            buf[..len].copy_from_slice(&h[..len]);
            (buf, len)
        })
    });
    let host_str = host_opt
        .as_ref()
        .and_then(|(buf, len)| core::str::from_utf8(&buf[..*len]).ok());

    send_deny_notify(audit_token, host_str, port, ip_opt, source_surface);
}

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
    // Look up the hostname in the per-process getaddrinfo cache. A cache hit
    // means the sockaddr was previously resolved via getaddrinfo for THIS
    // process — the tier-walk evaluator's `resolved_via_getaddrinfo` flag.
    let host = with_cache(|c| {
        // Copy the hostname out of the cache to avoid holding the lock
        // across the policy evaluation.
        c.lookup(&sa_buf[..sa_n]).map(|h| {
            let mut buf = [0u8; MAX_HOSTNAME];
            buf[..h.len()].copy_from_slice(h);
            (buf, h.len())
        })
    });

    // BLOCKER-01 fix: rebuild the (host_bytes, ip_bytes, resolved) triple and
    // delegate to `evaluate_policy`. The evaluator's hard rules cover
    // loopback (D-25a), cloud-metadata (D-25b), and raw-IP cache-miss
    // (D-25c / ALLOW-08) — the libc hot path now enforces them all, with
    // correct precedence even when a project allow tries to override.
    //
    // Render the IP for evaluator use (small stack buffer; no heap alloc).
    let mut ip_buf = [0u8; 64];
    let ip_slice: Option<&[u8]> = unsafe { ip_to_str(addr, addrlen, &mut ip_buf) };

    // -- Resolve-IPC fallback (gap-closure 02-08) --
    //
    // On cache miss, before falling through to the raw-IP cache-miss-deny path,
    // attempt to reverse-lookup the destination IP against the per-run snapshot's
    // Exact CuratedAllow / ProjectAllow hostname entries via the daemon's Resolve
    // handler (tag 0x06). If a match is found, populate the cache and re-issue
    // evaluate_policy with the resolved hostname.
    //
    // Guards (ALL must be true to enter the fallback):
    //   (a) host is None (cache miss)
    //   (b) destination family is AF_INET or AF_INET6
    //   (c) destination is NOT loopback (Tier 0a fires before cache in evaluate_policy;
    //       Resolve-IPC is redundant and wasteful for loopback)
    //   (d) destination is NOT cloud-metadata (same reason)
    //   (e) daemon socket IS configured (daemon_socket_path().is_some())
    let host = if host.is_none() && daemon_socket_path().is_some() {
        // Determine the address family from the raw sockaddr bytes.
        let af = if sa_n >= 2 { sa_buf[1] as i32 } else { 0 };
        let is_inet = af == AF_INET || af == AF_INET6;

        let not_loopback = ip_slice.map_or(true, |ip| !is_loopback_ip(ip));
        let not_imds = ip_slice.map_or(true, |ip| !is_cloud_metadata_ip(ip));

        if is_inet && not_loopback && not_imds {
            // Extract port from bytes [2..4] of the sockaddr wire buffer (BE u16).
            let port = if sa_n >= 4 {
                u16::from_be_bytes([sa_buf[2], sa_buf[3]])
            } else {
                0
            };

            // Walk Exact CuratedAllow / ProjectAllow entries, capped at MAX_RESOLVE_ATTEMPTS.
            let mut host_from_resolve: Option<(/* buf */ [u8; MAX_HOSTNAME], /* len */ usize)> = None;
            let mut attempts = 0usize;
            'resolve_walk: for entry in entries
                .iter()
                .filter(|e| {
                    e.kind == RuleKind::Allow
                        && (e.tier == RuleTier::CuratedAllow || e.tier == RuleTier::ProjectAllow)
                        && e.match_type == MatchType::Exact
                })
            {
                if attempts >= MAX_RESOLVE_ATTEMPTS {
                    break;
                }
                attempts += 1;

                match send_resolve_sync(&entry.pattern, port, RESOLVE_TIMEOUT_MS) {
                    Ok(addrs) => {
                        // Compare each returned sockaddr wire buffer against sa_buf[..sa_n].
                        // The daemon's sockaddr_to_wire uses sa_len as byte[0], so the
                        // match key is the first sa_n bytes of each wire buffer.
                        for wire_addr in &addrs {
                            // The wire addr is always SOCKADDR_WIRE_LEN bytes; compare
                            // up to sa_n bytes (the caller's addrlen).
                            let cmp_len = sa_n.min(SOCKADDR_WIRE_LEN);
                            if &wire_addr[..cmp_len] == &sa_buf[..cmp_len] {
                                // Match found: populate the cache so future connects
                                // to the same sockaddr are cache-hit-only.
                                with_cache(|c| c.insert(&sa_buf[..sa_n], entry.pattern.as_bytes()));
                                let mut hbuf = [0u8; MAX_HOSTNAME];
                                let hlen = entry.pattern.len().min(MAX_HOSTNAME);
                                hbuf[..hlen].copy_from_slice(&entry.pattern.as_bytes()[..hlen]);
                                host_from_resolve = Some((hbuf, hlen));
                                break 'resolve_walk;
                            }
                        }
                    }
                    Err(_) => {
                        // Resolve failed for this entry — skip and try the next.
                        // Do NOT fail-closed on a per-entry error; the next entry might match.
                        continue;
                    }
                }
            }
            host_from_resolve
        } else {
            None
        }
    } else {
        host
    };

    match host {
        Some((buf, n)) => {
            // Cache hit (or Resolve-IPC populated): getaddrinfo previously resolved this
            // destination OR we just populated via send_resolve_sync.
            evaluate_in_hook(&buf[..n], ip_slice, true, entries)
        }
        None => {
            // Cache miss: connect-by-IP with no prior resolution. Pass an
            // empty host so the evaluator tier-walks against the IP only;
            // the cache-miss-deny hard rule fires at this point unless the
            // destination is loopback (the loopback hard rule comes first
            // inside `evaluate_policy`).
            evaluate_in_hook(b"", ip_slice, false, entries)
        }
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

// ---- write ----

#[unsafe(no_mangle)]
pub unsafe extern "C" fn sentinel_write(
    fd: c_int,
    buf: *const c_void,
    count: size_t,
) -> ssize_t {
    // Fast path: non-socket fds pass through with ~1 bitmap lookup overhead.
    if !crate::fd_class::is_connected_socket(fd) {
        return unsafe { raw_syscall::raw_write(fd, buf, count) };
    }
    // Socket fd — the destination was already permitted at connect() time
    // for connected sockets. Pass through.
    unsafe { raw_syscall::raw_write(fd, buf, count) }
}

// ---- writev ----

#[unsafe(no_mangle)]
pub unsafe extern "C" fn sentinel_writev(
    fd: c_int,
    iov: *const libc::iovec,
    iovcnt: c_int,
) -> ssize_t {
    if !crate::fd_class::is_connected_socket(fd) {
        return unsafe { raw_syscall::raw_writev(fd, iov, iovcnt) };
    }
    unsafe { raw_syscall::raw_writev(fd, iov, iovcnt) }
}

// ---- send ----

#[unsafe(no_mangle)]
pub unsafe extern "C" fn sentinel_send(
    s: c_int,
    buf: *const c_void,
    len: size_t,
    flags: c_int,
) -> ssize_t {
    // BL-04: RAII guard — see reentrancy.rs for the canonical rationale.
    let _guard = match InHookGuard::enter() {
        Some(g) => g,
        None => return unsafe { raw_syscall::raw_send(s, buf, len, flags) },
    };
    // send() operates on a connected socket — the destination was already
    // permitted at connect() time. Pass through unconditionally.
    unsafe { raw_syscall::raw_send(s, buf, len, flags) }
    // _guard drops here: IN_HOOK cleared after real syscall returns
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
    fn send(
        s: c_int,
        buf: *const c_void,
        len: size_t,
        flags: c_int,
    ) -> ssize_t;
}

// M005-S01: getaddrinfo interpose re-enabled via daemon-proxied DNS.
// BL-05 infinite recursion is avoided by never calling real getaddrinfo —
// DNS is proxied through the daemon's Resolve IPC handler.
// freeaddrinfo is also interposed so our malloc'd addrinfo nodes are freed
// correctly (real freeaddrinfo would crash on our custom layout).

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

#[unsafe(no_mangle)]
#[unsafe(link_section = "__DATA,__interpose")]
#[used]
static SENTINEL_INTERPOSE_SEND: [SyncPtr; 2] = [
    SyncPtr(sentinel_send as *const c_void),
    SyncPtr(send as *const c_void),
];

#[unsafe(no_mangle)]
#[unsafe(link_section = "__DATA,__interpose")]
#[used]
static SENTINEL_INTERPOSE_WRITE: [SyncPtr; 2] = [
    SyncPtr(sentinel_write as *const c_void),
    SyncPtr(libc::write as *const c_void),
];

#[unsafe(no_mangle)]
#[unsafe(link_section = "__DATA,__interpose")]
#[used]
static SENTINEL_INTERPOSE_WRITEV: [SyncPtr; 2] = [
    SyncPtr(sentinel_writev as *const c_void),
    SyncPtr(libc::writev as *const c_void),
];

#[unsafe(no_mangle)]
#[unsafe(link_section = "__DATA,__interpose")]
#[used]
static SENTINEL_INTERPOSE_GETADDRINFO: [SyncPtr; 2] = [
    SyncPtr(sentinel_getaddrinfo as *const c_void),
    SyncPtr(libc::getaddrinfo as *const c_void),
];

#[unsafe(no_mangle)]
#[unsafe(link_section = "__DATA,__interpose")]
#[used]
static SENTINEL_INTERPOSE_FREEADDRINFO: [SyncPtr; 2] = [
    SyncPtr(sentinel_freeaddrinfo as *const c_void),
    SyncPtr(libc::freeaddrinfo as *const c_void),
];

// syscall() interpose: DEFERRED.
//
// libc's syscall(int, ...) uses C variadic calling convention. On aarch64
// macOS, variadic args are passed on the stack (not in registers), so a
// non-variadic Rust function cannot correctly extract the args. Rust's
// c_variadic feature is unstable. Until it stabilizes, the syscall()
// interpose is not viable.
//
// Impact: malicious code that calls syscall(SYS_CONNECT, ...) directly
// bypasses sentinel_connect. This is a known gap — realistic supply-chain
// attacks use connect() or higher-level APIs, not raw syscall().
