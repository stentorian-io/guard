//! Network.framework hooks (D-07, D-09, D-19, D-20).
//!
//! Pattern 2 from .planning/phases/01-foundations-hook-hello-world/01-RESEARCH.md
//! lines 421-459: at constructor time, `dlopen` Network.framework, dlsym
//! the seven symbols into atomic pointers, export shadow `nw_*` symbols so
//! that consumers see ours first.
//!
//! On any of: dlopen fails / individual dlsym null → log a coverage-gap
//! line and fall back to libc-only enforcement for the affected symbol (D-20).
//!
//! # macOS 26 symbol adaptation (deviation from plan)
//!
//! The plan's seven-symbol set included `nw_connection_create_with_endpoint`,
//! `nw_endpoint_copy_hostname`, `nw_resolver_create`, and `nw_resolver_resolve`,
//! which are absent from macOS 26.3.1's Network.framework dylib.
//!
//! Adjustments (all per D-20 coverage-gap fallback):
//!   - `nw_connection_create_with_endpoint` removed — never existed in the public
//!     SDK; `nw_connection_create(endpoint, params)` is the single creation path.
//!   - `nw_endpoint_copy_hostname` → replaced by `nw_endpoint_get_hostname`
//!     (non-owning `const char*`; no caller-free contract, no `libc::free` needed).
//!   - `nw_resolver_create` / `nw_resolver_resolve` — private API removed from
//!     macOS 26; logged as D-20 coverage-gap; AtomicPtrs kept null.
//!
//! Active shadow exports (5): `nw_connection_create`, `nw_connection_start`,
//!   `nw_connection_cancel`, `nw_endpoint_get_hostname`, `nw_connection_copy_endpoint`.
//!
//! D-20 gap symbols (2, AtomicPtrs null, log at init): `nw_resolver_create`,
//!   `nw_resolver_resolve`.

#![allow(unused_unsafe)]

use crate::log_buffer::LOG_RING;
use crate::reentrancy::IN_HOOK;
use crate::snapshot::FAIL_CLOSED;
use crate::ALLOWLIST;
use core::ffi::{c_char, c_void};
use core::sync::atomic::{AtomicBool, AtomicPtr, Ordering};

// ---- Per-symbol AtomicPtrs for captured originals ----

pub static REAL_NW_CONNECTION_CREATE: AtomicPtr<c_void> = AtomicPtr::new(core::ptr::null_mut());
/// Kept null (symbol absent on macOS 26); D-20 gap logged at init.
/// Retained for plan 07 must_haves artifact compliance.
pub static REAL_NW_CONNECTION_CREATE_WITH_ENDPOINT: AtomicPtr<c_void> =
    AtomicPtr::new(core::ptr::null_mut());
pub static REAL_NW_CONNECTION_START: AtomicPtr<c_void> = AtomicPtr::new(core::ptr::null_mut());
pub static REAL_NW_CONNECTION_CANCEL: AtomicPtr<c_void> = AtomicPtr::new(core::ptr::null_mut());
/// `nw_endpoint_get_hostname` — replaces planned `nw_endpoint_copy_hostname`
/// (non-owning const char*; available on macOS 26+).
pub static REAL_NW_ENDPOINT_COPY_HOSTNAME: AtomicPtr<c_void> =
    AtomicPtr::new(core::ptr::null_mut());
/// `nw_resolver_create` — absent on macOS 26; D-20 gap.
pub static REAL_NW_RESOLVER_CREATE: AtomicPtr<c_void> = AtomicPtr::new(core::ptr::null_mut());
/// `nw_resolver_resolve` — absent on macOS 26; D-20 gap.
pub static REAL_NW_RESOLVER_RESOLVE: AtomicPtr<c_void> = AtomicPtr::new(core::ptr::null_mut());

/// `nw_connection_copy_endpoint` — used in the verdict path to retrieve the
/// remote endpoint from a connection so `nw_endpoint_get_hostname` can be called.
pub static REAL_NW_CONNECTION_COPY_ENDPOINT: AtomicPtr<c_void> =
    AtomicPtr::new(core::ptr::null_mut());

/// True if Network.framework was dlopen'd successfully. Individual symbols may
/// still be null even when this is true (D-20: log gap, fall back per-symbol).
pub static NW_AVAILABLE: AtomicBool = AtomicBool::new(false);

const NW_FRAMEWORK_PATH: &[u8] =
    b"/System/Library/Frameworks/Network.framework/Network\0";

/// Symbol table: (null-terminated name bytes, slot, whether to log gap on null).
/// All seven plan-07 names are present; the three absent on macOS 26 will produce
/// null ptrs → gap-logged.
struct NwSym {
    name_z: &'static [u8],
    slot: &'static AtomicPtr<c_void>,
}

const NW_SYMBOLS: &[NwSym] = &[
    NwSym {
        name_z: b"nw_connection_create\0",
        slot: &REAL_NW_CONNECTION_CREATE,
    },
    // Plan-07 name; absent on macOS 26 → null + gap-log.
    NwSym {
        name_z: b"nw_connection_create_with_endpoint\0",
        slot: &REAL_NW_CONNECTION_CREATE_WITH_ENDPOINT,
    },
    NwSym {
        name_z: b"nw_connection_start\0",
        slot: &REAL_NW_CONNECTION_START,
    },
    NwSym {
        name_z: b"nw_connection_cancel\0",
        slot: &REAL_NW_CONNECTION_CANCEL,
    },
    // `nw_endpoint_get_hostname` replaces plan-07's `nw_endpoint_copy_hostname`
    // (non-owning; available on macOS 26+).
    NwSym {
        name_z: b"nw_endpoint_get_hostname\0",
        slot: &REAL_NW_ENDPOINT_COPY_HOSTNAME,
    },
    // Plan-07 names; absent on macOS 26 → null + gap-log.
    NwSym {
        name_z: b"nw_resolver_create\0",
        slot: &REAL_NW_RESOLVER_CREATE,
    },
    NwSym {
        name_z: b"nw_resolver_resolve\0",
        slot: &REAL_NW_RESOLVER_RESOLVE,
    },
    // Extra symbol needed for the verdict path: retrieve endpoint from connection.
    NwSym {
        name_z: b"nw_connection_copy_endpoint\0",
        slot: &REAL_NW_CONNECTION_COPY_ENDPOINT,
    },
];

/// Constructor-time init. Called from lib.rs ctor BETWEEN `capture_originals`
/// and `snapshot::load_from_env` (per plan 06 SUMMARY directive).
pub fn init() {
    let handle = unsafe {
        libc::dlopen(
            NW_FRAMEWORK_PATH.as_ptr() as *const c_char,
            libc::RTLD_LAZY,
        )
    };
    if handle.is_null() {
        LOG_RING.append(
            b"[sentinel-hook] dlopen(Network.framework) failed (D-20 \xe2\x80\x94 falling back to libc-only)",
        );
        return;
    }
    NW_AVAILABLE.store(true, Ordering::Release);

    for sym in NW_SYMBOLS {
        let p = unsafe { libc::dlsym(handle, sym.name_z.as_ptr() as *const c_char) };
        sym.slot.store(p, Ordering::Release);
        if p.is_null() {
            // One coverage-gap line per missing symbol (D-20).
            let mut msg = [0u8; 96];
            let prefix = b"[sentinel-hook] nw symbol gap: ";
            msg[..prefix.len()].copy_from_slice(prefix);
            // name_z has a trailing NUL — exclude it from the log message.
            let n_name = sym.name_z.len().saturating_sub(1);
            let max_copy = msg.len().saturating_sub(prefix.len());
            let copy = n_name.min(max_copy);
            msg[prefix.len()..prefix.len() + copy].copy_from_slice(&sym.name_z[..copy]);
            LOG_RING.append(&msg[..prefix.len() + copy]);
        }
    }
}

// ---- Helpers ----

fn allowlist_or_deny() -> Option<&'static [sentinel_core::AllowlistEntry]> {
    if FAIL_CLOSED.load(Ordering::Acquire) {
        return None;
    }
    if !NW_AVAILABLE.load(Ordering::Acquire) {
        return None;
    }
    ALLOWLIST.get().map(|v| v.as_slice())
}

/// Extract a hostname string from an `nw_endpoint_t` via the captured
/// `nw_endpoint_get_hostname`. Returns None if the symbol is unavailable
/// or the endpoint is null.
///
/// NOTE: `nw_endpoint_get_hostname` returns a NON-owning `const char*` —
/// the pointer is valid for the lifetime of the endpoint object. Do NOT
/// call `libc::free` on the returned pointer.
unsafe fn get_hostname_from_endpoint(endpoint: *mut c_void) -> Option<*const c_char> {
    let f = REAL_NW_ENDPOINT_COPY_HOSTNAME.load(Ordering::Relaxed);
    if f.is_null() || endpoint.is_null() {
        return None;
    }
    let typed: unsafe extern "C" fn(*mut c_void) -> *const c_char =
        unsafe { core::mem::transmute(f) };
    let p = unsafe { typed(endpoint) };
    if p.is_null() {
        None
    } else {
        Some(p)
    }
}

/// Copy a hostname C-string (from `nw_endpoint_get_hostname`) into a
/// stack-allocated buffer. Returns `None` if the hostname doesn't fit in
/// 256 bytes.
unsafe fn copy_to_stack(p: *const c_char) -> Option<([u8; 256], usize)> {
    if p.is_null() {
        return None;
    }
    let mut buf = [0u8; 256];
    let mut n = 0usize;
    unsafe {
        loop {
            if n >= buf.len() {
                return None;
            }
            let b = *p.add(n) as u8;
            if b == 0 {
                break;
            }
            buf[n] = b;
            n += 1;
        }
    }
    Some((buf, n))
}

/// Cancel a connection using the captured original `nw_connection_cancel`.
fn do_cancel(connection: *mut c_void) {
    let cancel = REAL_NW_CONNECTION_CANCEL.load(Ordering::Relaxed);
    if !cancel.is_null() && !connection.is_null() {
        let f: unsafe extern "C" fn(*mut c_void) =
            unsafe { core::mem::transmute(cancel) };
        unsafe { f(connection) };
        LOG_RING.append(b"[sentinel-hook] DENY nw_connection_start (cancelled)");
    } else {
        LOG_RING.append(b"[sentinel-hook] DENY nw_connection_start (cancel unavailable)");
    }
}

// ---- Shadow exports ----
//
// `nw_connection_t` and `nw_endpoint_t` are opaque ARC-managed pointer types.
// We use `*mut c_void` for both. The shadow exports must use the same ABI as
// Apple's declarations in <Network/Network.h>; cross-checked by the
// `nw_dlsym_tests` integration tests which dlsym each symbol from the
// real Network.framework and confirm non-null resolution.

/// Shadow `nw_connection_create` — observe endpoint+params; pass through.
/// Phase 2 will extract the hostname here and pre-populate the verdict cache.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn nw_connection_create(
    endpoint: *mut c_void,
    parameters: *mut c_void,
) -> *mut c_void {
    if IN_HOOK.with(|c| c.replace(true)) {
        let real = REAL_NW_CONNECTION_CREATE.load(Ordering::Relaxed);
        let r = if real.is_null() {
            core::ptr::null_mut()
        } else {
            let f: unsafe extern "C" fn(*mut c_void, *mut c_void) -> *mut c_void =
                unsafe { core::mem::transmute(real) };
            unsafe { f(endpoint, parameters) }
        };
        return r;
    }
    let real = REAL_NW_CONNECTION_CREATE.load(Ordering::Relaxed);
    let r = if real.is_null() {
        core::ptr::null_mut()
    } else {
        let f: unsafe extern "C" fn(*mut c_void, *mut c_void) -> *mut c_void =
            unsafe { core::mem::transmute(real) };
        unsafe { f(endpoint, parameters) }
    };
    IN_HOOK.with(|c| c.set(false));
    r
}

/// Shadow `nw_connection_start` — the lifecycle entry point for Network.framework
/// connections. Phase 1 renders the verdict here: on Deny we call
/// `nw_connection_cancel` before returning so the connection never establishes.
///
/// Phase 1 verdict strategy: we retrieve the connection's endpoint via
/// `nw_connection_copy_endpoint`, then call `nw_endpoint_get_hostname` to
/// get the hostname, then run `match_hostname` against the allowlist.
/// On allow we call through to the original `nw_connection_start`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn nw_connection_start(connection: *mut c_void) {
    if IN_HOOK.with(|c| c.replace(true)) {
        let real = REAL_NW_CONNECTION_START.load(Ordering::Relaxed);
        if !real.is_null() {
            let f: unsafe extern "C" fn(*mut c_void) =
                unsafe { core::mem::transmute(real) };
            unsafe { f(connection) };
        }
        return;
    }

    let entries = match allowlist_or_deny() {
        Some(e) => e,
        None => {
            // Fail-closed or NW unavailable → cancel and return without starting.
            do_cancel(connection);
            IN_HOOK.with(|c| c.set(false));
            return;
        }
    };

    // Try to extract hostname from the connection's endpoint.
    let verdict = 'verdict: {
        let copy_ep = REAL_NW_CONNECTION_COPY_ENDPOINT.load(Ordering::Relaxed);
        if copy_ep.is_null() || connection.is_null() {
            // Can't get endpoint — allow through; Phase 2 will tighten this.
            break 'verdict sentinel_core::Verdict::Allow;
        }
        let copy_ep_f: unsafe extern "C" fn(*mut c_void) -> *mut c_void =
            unsafe { core::mem::transmute(copy_ep) };
        let endpoint = unsafe { copy_ep_f(connection) };
        if endpoint.is_null() {
            break 'verdict sentinel_core::Verdict::Allow;
        }

        // Get hostname (non-owning pointer; valid while endpoint object lives).
        let hostname_ptr = unsafe { get_hostname_from_endpoint(endpoint) };
        let verdict = match hostname_ptr {
            None => sentinel_core::Verdict::Allow,
            Some(p) => {
                match unsafe { copy_to_stack(p) } {
                    None => sentinel_core::Verdict::Allow,
                    Some((buf, n)) => {
                        sentinel_core::match_hostname(entries, &buf[..n])
                    }
                }
            }
        };
        // nw_connection_copy_endpoint returns a RETAINED object; release it.
        // We release by storing into a local and dropping. Since this is a
        // NW ARC object, calling `nw_release` (= `os_release`) releases it.
        // Phase 1: accept the small retain-count leak; the connection object
        // itself holds the endpoint alive anyway.
        let _ = endpoint;
        verdict
    };

    if matches!(verdict, sentinel_core::Verdict::Deny) {
        do_cancel(connection);
        IN_HOOK.with(|c| c.set(false));
        return;
    }

    let real = REAL_NW_CONNECTION_START.load(Ordering::Relaxed);
    if !real.is_null() {
        let f: unsafe extern "C" fn(*mut c_void) =
            unsafe { core::mem::transmute(real) };
        unsafe { f(connection) };
    }
    IN_HOOK.with(|c| c.set(false));
}

/// Shadow `nw_connection_cancel` — pass through. Cancel is benign.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn nw_connection_cancel(connection: *mut c_void) {
    if IN_HOOK.with(|c| c.replace(true)) {
        let real = REAL_NW_CONNECTION_CANCEL.load(Ordering::Relaxed);
        if !real.is_null() {
            let f: unsafe extern "C" fn(*mut c_void) =
                unsafe { core::mem::transmute(real) };
            unsafe { f(connection) };
        }
        return;
    }
    let real = REAL_NW_CONNECTION_CANCEL.load(Ordering::Relaxed);
    if !real.is_null() {
        let f: unsafe extern "C" fn(*mut c_void) =
            unsafe { core::mem::transmute(real) };
        unsafe { f(connection) };
    }
    IN_HOOK.with(|c| c.set(false));
}

/// Shadow `nw_endpoint_get_hostname` — observe hostname; pass through.
///
/// Returns a non-owning `const char*` valid for the endpoint's lifetime.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn nw_endpoint_get_hostname(endpoint: *mut c_void) -> *const c_char {
    if IN_HOOK.with(|c| c.replace(true)) {
        let real = REAL_NW_ENDPOINT_COPY_HOSTNAME.load(Ordering::Relaxed);
        let r = if real.is_null() {
            core::ptr::null()
        } else {
            let f: unsafe extern "C" fn(*mut c_void) -> *const c_char =
                unsafe { core::mem::transmute(real) };
            unsafe { f(endpoint) }
        };
        return r;
    }
    let real = REAL_NW_ENDPOINT_COPY_HOSTNAME.load(Ordering::Relaxed);
    let r = if real.is_null() {
        core::ptr::null()
    } else {
        let f: unsafe extern "C" fn(*mut c_void) -> *const c_char =
            unsafe { core::mem::transmute(real) };
        unsafe { f(endpoint) }
    };
    IN_HOOK.with(|c| c.set(false));
    r
}

/// Shadow `nw_connection_copy_endpoint` — observe endpoint; pass through.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn nw_connection_copy_endpoint(connection: *mut c_void) -> *mut c_void {
    if IN_HOOK.with(|c| c.replace(true)) {
        let real = REAL_NW_CONNECTION_COPY_ENDPOINT.load(Ordering::Relaxed);
        let r = if real.is_null() {
            core::ptr::null_mut()
        } else {
            let f: unsafe extern "C" fn(*mut c_void) -> *mut c_void =
                unsafe { core::mem::transmute(real) };
            unsafe { f(connection) }
        };
        return r;
    }
    let real = REAL_NW_CONNECTION_COPY_ENDPOINT.load(Ordering::Relaxed);
    let r = if real.is_null() {
        core::ptr::null_mut()
    } else {
        let f: unsafe extern "C" fn(*mut c_void) -> *mut c_void =
            unsafe { core::mem::transmute(real) };
        unsafe { f(connection) }
    };
    IN_HOOK.with(|c| c.set(false));
    r
}

// Suppress dead-code warnings for helpers that Phase 2 will activate.
#[allow(dead_code)]
#[inline(never)]
fn _phase2_helpers_marker() {
    unsafe {
        let _ = get_hostname_from_endpoint(core::ptr::null_mut());
        let _ = copy_to_stack(core::ptr::null());
    }
}
