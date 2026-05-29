//! Network.framework hooks (D-07, D-09, D-19, D-20).
//!
//! At constructor time, `dlopen` Network.framework, dlsym the seven symbols
//! into atomic pointers, export shadow `nw_*` symbols so that consumers see
//! ours first.
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
//!     macOS 26; logged as D-20 coverage-gap; `AtomicPtrs` kept null.
//!
//! Active shadow exports (5): `nw_connection_create`, `nw_connection_start`,
//!   `nw_connection_cancel`, `nw_endpoint_get_hostname`, `nw_connection_copy_endpoint`.
//!
//! D-20 gap symbols (2, `AtomicPtrs` null, log at init): `nw_resolver_create`,
//!   `nw_resolver_resolve`.

use crate::ALLOWLIST;
use crate::log_buffer::LOG_RING;
use crate::reentrancy::IN_HOOK;
use crate::snapshot::FAIL_CLOSED;
use core::ffi::{CStr, c_char, c_void};
use core::sync::atomic::{AtomicBool, AtomicPtr, Ordering};

// Objective-C runtime — used by `is_nw_object` to gate calls to NW APIs on
// pointers that may or may not be NW objects (libuv passes opaque non-NW
// pointers through `nw_connection_start`; v0.1 left this as a pass-through,
// v0.2 added proper verdict extraction).
//
// Resolved via dlsym at runtime instead of a static link to libobjc —
// explicitly linking libobjc changes dyld's init order and contributes to
// dispatch_once reentrancy crashes on macOS 26+. The ObjC runtime is
// always loaded by libSystem so dlsym(RTLD_DEFAULT) finds it.
static REAL_OBJECT_GET_CLASS_NAME: AtomicPtr<c_void> = AtomicPtr::new(core::ptr::null_mut());

fn resolve_object_get_class_name() -> Option<unsafe extern "C" fn(*mut c_void) -> *const c_char> {
    let p = REAL_OBJECT_GET_CLASS_NAME.load(Ordering::Relaxed);
    if !p.is_null() {
        return Some(unsafe {
            core::mem::transmute::<*mut c_void, unsafe extern "C" fn(*mut c_void) -> *const c_char>(
                p,
            )
        });
    }
    let sym = unsafe { libc::dlsym(libc::RTLD_DEFAULT, c"object_getClassName".as_ptr()) };
    if sym.is_null() {
        return None;
    }
    REAL_OBJECT_GET_CLASS_NAME.store(sym, Ordering::Relaxed);
    Some(unsafe {
        core::mem::transmute::<*mut c_void, unsafe extern "C" fn(*mut c_void) -> *const c_char>(sym)
    })
}

// ---- Per-symbol AtomicPtrs for captured originals ----

pub static REAL_NW_CONNECTION_CREATE: AtomicPtr<c_void> = AtomicPtr::new(core::ptr::null_mut());
/// Kept null (symbol absent on macOS 26); D-20 gap logged at init.
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

const NW_FRAMEWORK_PATH: &[u8] = b"/System/Library/Frameworks/Network.framework/Network\0";

/// Symbol table: (null-terminated name bytes, slot, whether to log gap on null).
/// All seven v0.1 names are present; the three absent on macOS 26 will produce
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
    // v0.1 name; absent on macOS 26 → null + gap-log.
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
    // `nw_endpoint_get_hostname` replaces v0.1's `nw_endpoint_copy_hostname`
    // (non-owning; available on macOS 26+).
    NwSym {
        name_z: b"nw_endpoint_get_hostname\0",
        slot: &REAL_NW_ENDPOINT_COPY_HOSTNAME,
    },
    // v0.1 names; absent on macOS 26 → null + gap-log.
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

/// Deferred init — called lazily from each NW shadow export on first use.
///
/// Moved out of the ctor to avoid `dispatch_once` reentrancy deadlock on
/// macOS 26+: dlopen(Network.framework) during the dylib constructor
/// triggers CoreFoundation initialization which re-enters `dispatch_once`
/// in Network.framework's own init chain, crashing the process.
pub fn ensure_init() {
    use std::sync::Once;
    static INIT: Once = Once::new();
    INIT.call_once(|| {
        let handle = unsafe {
            libc::dlopen(
                NW_FRAMEWORK_PATH.as_ptr().cast::<c_char>(),
                libc::RTLD_LAZY,
            )
        };
        if handle.is_null() {
            LOG_RING.append(
                b"[guard-hook] dlopen(Network.framework) failed (D-20 \xe2\x80\x94 falling back to libc-only)",
            );
            return;
        }
        NW_AVAILABLE.store(true, Ordering::Release);

        for sym in NW_SYMBOLS {
            let p = unsafe { libc::dlsym(handle, sym.name_z.as_ptr().cast::<c_char>()) };
            sym.slot.store(p, Ordering::Release);
            if p.is_null() {
                let mut msg = [0u8; 96];
                let prefix = b"[guard-hook] nw symbol gap: ";
                msg[..prefix.len()].copy_from_slice(prefix);
                let n_name = sym.name_z.len().saturating_sub(1);
                let max_copy = msg.len().saturating_sub(prefix.len());
                let copy = n_name.min(max_copy);
                msg[prefix.len()..prefix.len() + copy].copy_from_slice(&sym.name_z[..copy]);
                LOG_RING.append(&msg[..prefix.len() + copy]);
            }
        }
    });
}

// ---- Helpers ----

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
    if p.is_null() { None } else { Some(p) }
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
            let b = *p.cast::<u8>().add(n);
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
        let f: unsafe extern "C" fn(*mut c_void) = unsafe { core::mem::transmute(cancel) };
        unsafe { f(connection) };
        LOG_RING.append(b"[guard-hook] DENY nw_connection_start (cancelled)");
    } else {
        LOG_RING.append(b"[guard-hook] DENY nw_connection_start (cancel unavailable)");
    }
}

// ---- D-41 closure: safe object-type detection ------------------------------
//
// v0.1 left `nw_connection_start` as a pass-through because calling
// `nw_connection_copy_endpoint` on a libuv-internal opaque pointer crashes
// the wrapped process (libuv's nw_connection_t-shaped pointer is NOT an
// actual NW object — node's I/O subsystem reuses NW symbols for its own
// handles). Mitigation: gate every NW API call on a class-name check via
// the Objective-C runtime.
//
// `object_getClassName` is the documented runtime API for retrieving the class
// name of an Objective-C instance. NW.framework objects all have class names
// starting with `OS_nw_` (e.g. `OS_nw_connection`, `OS_nw_endpoint_host`,
// `OS_nw_resolver`). A libuv handle does NOT — it's a plain C struct with no
// Objective-C class metadata.
//
// IMPORTANT — failure modes of object_getClassName on truly bogus pointers:
//   - On valid Objective-C objects: returns the class name C-string.
//   - On non-objc pointers that happen to live in mapped memory: usually
//     returns NULL or a benign pointer that won't decode as `OS_nw_`-prefixed.
//   - On freed/unmapped memory: may segfault. We accept that small risk
//     because libuv's pointers ARE in mapped memory (they're live handles).
//
// The check is therefore: "if the pointer's class name starts with `OS_nw_`,
// it's safe to call NW APIs on it; otherwise pass through unchanged".

/// Returns true if `ptr` points to an Objective-C object whose class name
/// starts with `OS_nw_`. Used to gate calls to `nw_endpoint_get_hostname` and
/// related NW APIs in the verdict path. v0.1 saw crashes when libuv passed
/// opaque non-NW pointers through `nw_connection_start`; this gate replaces
/// the pass-through with a safe class-name check (D-41).
#[inline]
/// Returns true when the pointer appears to reference a Network.framework object.
///
/// # Safety
///
/// `ptr` must be null or point to mapped memory that is safe for
/// `object_getClassName` to inspect.
pub unsafe fn is_nw_object(ptr: *mut c_void) -> bool {
    if ptr.is_null() {
        return false;
    }
    let Some(get_class_name) = resolve_object_get_class_name() else {
        return false;
    };
    let cls = unsafe { get_class_name(ptr) };
    if cls.is_null() {
        return false;
    }
    let bytes = unsafe { CStr::from_ptr(cls) }.to_bytes();
    bytes.starts_with(b"OS_nw_")
}

/// Render the verdict for an NW connection: extract its endpoint, get the
/// hostname, run `evaluate_policy` against the loaded ALLOWLIST. Returns
/// `true` if the verdict is Deny. Returns `false` (pass-through / fail-open)
/// on any failure to extract the hostname, on `FAIL_CLOSED` state, or on
/// missing NW symbols — the libc connect-level enforcement still catches
/// the connection in those degraded paths.
fn decide_for_nw_connection(connection: *mut c_void) -> bool {
    use crate::log_buffer::LOG_RING;
    use guard_core::Verdict;
    if FAIL_CLOSED.load(Ordering::Acquire) {
        return false;
    }
    let Some(host_bytes) = extract_endpoint_hostname(connection) else {
        return false;
    };
    let entries: &[guard_core::AllowlistEntry] =
        ALLOWLIST.get().map_or(&[], std::vec::Vec::as_slice);
    let (verdict, source) = guard_core::policy::evaluate_policy(&host_bytes, None, true, entries);
    if matches!(verdict, Verdict::Deny) {
        let host_str = core::str::from_utf8(&host_bytes).unwrap_or("<non-utf8>");
        let msg = format!(
            "[guard-hook] DENY nw_connection_start {} ({})",
            host_str,
            source.as_label()
        );
        LOG_RING.append(msg.as_bytes());
        true
    } else {
        false
    }
}

/// Extract the hostname from an NW connection's endpoint. Returns `None` on
/// any failure path; the caller treats `None` as pass-through (fail-open) to
/// preserve v0.1 no-crash semantics on partial NW symbol availability.
///
/// Implementation: `nw_connection_copy_endpoint` → `nw_endpoint_get_hostname`
/// (cached at ctor time; D-20 logs gaps). Both calls are gated by
/// `is_nw_object` on the caller side (`nw_connection_start` shadow), so we
/// can call NW APIs without the libuv-pointer crash risk.
///
/// NOTE on the v0.2-vs-v0.3 split: this function returns `None` if
/// either `nw_connection_copy_endpoint` or `nw_endpoint_get_hostname` is
/// absent on the running OS (D-20 gap). On macOS 26.x both ARE present per
/// `replace_nw::init`, so the typical path yields a real hostname. The
/// libc connect path remains the dominant attack-surface enforcement and is
/// not affected by this NW-only path's failure modes.
fn extract_endpoint_hostname(connection: *mut c_void) -> Option<Vec<u8>> {
    if connection.is_null() {
        return None;
    }
    let copy_endpoint = REAL_NW_CONNECTION_COPY_ENDPOINT.load(Ordering::Relaxed);
    if copy_endpoint.is_null() {
        return None;
    }
    // SAFETY: caller guarantees `connection` is_nw_object; copy_endpoint was
    // dlsym'd at ctor time. The returned endpoint is an ARC-managed
    // nw_endpoint_t — borrowing it for the duration of the get-hostname call
    // is safe since we don't hold it past return.
    let endpoint: *mut c_void = unsafe {
        let f: unsafe extern "C" fn(*mut c_void) -> *mut c_void =
            core::mem::transmute(copy_endpoint);
        f(connection)
    };
    if endpoint.is_null() {
        return None;
    }
    // The endpoint must itself be an OS_nw_* object — defense in depth in
    // case copy_endpoint returned an unexpected pointer.
    if !unsafe { is_nw_object(endpoint) } {
        return None;
    }
    let p_host = unsafe { get_hostname_from_endpoint(endpoint) }?;
    let (buf, n) = unsafe { copy_to_stack(p_host) }?;
    Some(buf[..n].to_vec())
}

// ---- Shadow exports ----
//
// `nw_connection_t` and `nw_endpoint_t` are opaque ARC-managed pointer types.
// We use `*mut c_void` for both. The shadow exports must use the same ABI as
// Apple's declarations in <Network/Network.h>; cross-checked by the
// `nw_dlsym_tests` integration tests which dlsym each symbol from the
// real Network.framework and confirm non-null resolution.

/// Shadow `nw_connection_create` — observe endpoint+params; pass through.
///
/// # Safety
///
/// `endpoint` and `parameters` must satisfy Network.framework's
/// `nw_connection_create` contract.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn nw_connection_create(
    endpoint: *mut c_void,
    parameters: *mut c_void,
) -> *mut c_void {
    ensure_init();
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

/// Shadow `nw_connection_start` — verdict path with safe `is_nw_object` gate
/// (D-41 closure).
///
/// v0.1 left this as a pass-through after observing SIGSEGV on libuv's
/// internal opaque pointers (node's I/O subsystem reuses `nw_connection_start`
/// for non-NW handles). v0.2 D-41 closure: gate every NW API call on
/// `is_nw_object` so non-NW pointers fall through to the real symbol
/// unchanged (preserving v0.1's no-crash semantics) while real NW
/// connections render through `evaluate_policy`.
///
/// On Deny, calls `do_cancel(connection)` and RETURNS without invoking the
/// real `nw_connection_start` (T-02-06b-04: cancel-before-start ordering
/// prevents the connection from being established).
///
/// On Allow / no-match / extraction failure, falls through to the real
/// `nw_connection_start`. The libc connect/getaddrinfo path remains the
/// dominant supply-chain enforcement layer and is unaffected.
///
/// # Safety
///
/// `connection` must satisfy Network.framework's `nw_connection_start`
/// contract.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn nw_connection_start(connection: *mut c_void) {
    ensure_init();
    if IN_HOOK.with(|c| c.replace(true)) {
        let real = REAL_NW_CONNECTION_START.load(Ordering::Relaxed);
        if !real.is_null() {
            let f: unsafe extern "C" fn(*mut c_void) = unsafe { core::mem::transmute(real) };
            unsafe { f(connection) };
        }
        return;
    }

    // D-41: safe object-type detection BEFORE calling NW APIs. If `connection`
    // is not an OS_nw_* Objective-C object (libuv opaque pointer or similar),
    // pass through unchanged. Preserves v0.1's no-crash behavior on
    // non-NW callers.
    if !unsafe { is_nw_object(connection) } {
        let real = REAL_NW_CONNECTION_START.load(Ordering::Relaxed);
        if !real.is_null() {
            let f: unsafe extern "C" fn(*mut c_void) = unsafe { core::mem::transmute(real) };
            unsafe { f(connection) };
        }
        IN_HOOK.with(|c| c.set(false));
        return;
    }

    // Confirmed NW object — render verdict.
    let verdict_is_deny = decide_for_nw_connection(connection);
    if verdict_is_deny {
        // T-02-06b-04: cancel BEFORE calling the real nw_connection_start so
        // the connection never reaches the network.
        do_cancel(connection);
        IN_HOOK.with(|c| c.set(false));
        return;
    }

    // Allow / no-match / extraction failure — pass through to the real symbol.
    let real = REAL_NW_CONNECTION_START.load(Ordering::Relaxed);
    if !real.is_null() {
        let f: unsafe extern "C" fn(*mut c_void) = unsafe { core::mem::transmute(real) };
        unsafe { f(connection) };
    }
    IN_HOOK.with(|c| c.set(false));
}

/// Shadow `nw_connection_cancel` — pass through. Cancel is benign.
///
/// # Safety
///
/// `connection` must satisfy Network.framework's `nw_connection_cancel`
/// contract.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn nw_connection_cancel(connection: *mut c_void) {
    ensure_init();
    if IN_HOOK.with(|c| c.replace(true)) {
        let real = REAL_NW_CONNECTION_CANCEL.load(Ordering::Relaxed);
        if !real.is_null() {
            let f: unsafe extern "C" fn(*mut c_void) = unsafe { core::mem::transmute(real) };
            unsafe { f(connection) };
        }
        return;
    }
    let real = REAL_NW_CONNECTION_CANCEL.load(Ordering::Relaxed);
    if !real.is_null() {
        let f: unsafe extern "C" fn(*mut c_void) = unsafe { core::mem::transmute(real) };
        unsafe { f(connection) };
    }
    IN_HOOK.with(|c| c.set(false));
}

/// Shadow `nw_endpoint_get_hostname` — observe hostname; pass through.
///
/// Returns a non-owning `const char*` valid for the endpoint's lifetime.
///
/// # Safety
///
/// `endpoint` must satisfy Network.framework's `nw_endpoint_get_hostname`
/// contract.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn nw_endpoint_get_hostname(endpoint: *mut c_void) -> *const c_char {
    ensure_init();
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
///
/// # Safety
///
/// `connection` must satisfy Network.framework's
/// `nw_connection_copy_endpoint` contract.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn nw_connection_copy_endpoint(connection: *mut c_void) -> *mut c_void {
    ensure_init();
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

// `get_hostname_from_endpoint`, `copy_to_stack`, `do_cancel`, and
// `allowlist_or_deny` are all reachable from the v0.2 verdict path —
// `decide_for_nw_connection` and `extract_endpoint_hostname` invoke them.
