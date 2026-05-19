//! Verifies A6: that `nw_connection_cancel` (and the core set) resolve via
//! dlsym on the build machine (macOS 15+). This calls dlopen + dlsym DIRECTLY
//! — independent of the dylib's ctor — so the test passes/fails based on the
//! runtime OS support, not the dylib's loader path.
//!
//! # Symbol set adaptation for macOS 26
//!
//! Three of the original v0.1 symbols are absent on macOS 26.3.1:
//!   - `nw_connection_create_with_endpoint` — never in the public SDK;
//!     D-20 gap (null ptr, logged at init).
//!   - `nw_endpoint_copy_hostname` — replaced by `nw_endpoint_get_hostname`
//!     (non-owning `const char*`; available on macOS 26+).
//!   - `nw_resolver_create` / `nw_resolver_resolve` — private API removed from
//!     macOS 26; D-20 gaps.
//!
//! The `all_v1_nw_symbols_resolvable` test asserts only the AVAILABLE
//! symbols on macOS 26+. The D-20 gap symbols are tested separately in
//! `gap_symbols_are_null_on_macos26`.

use std::ffi::c_void;

const NW_PATH: &[u8] = b"/System/Library/Frameworks/Network.framework/Network\0";

fn dlopen_nw() -> Option<*mut c_void> {
    let h = unsafe { libc::dlopen(NW_PATH.as_ptr() as *const _, libc::RTLD_LAZY) };
    if h.is_null() { None } else { Some(h) }
}

fn dlsym_nw(handle: *mut c_void, name_z: &[u8]) -> *mut c_void {
    unsafe { libc::dlsym(handle, name_z.as_ptr() as *const _) }
}

#[test]
fn network_framework_dlopen_succeeds_on_build_machine() {
    assert!(dlopen_nw().is_some(), "Network.framework must dlopen on macOS 15+ (D-12 floor)");
}

#[test]
fn nw_connection_cancel_resolves_via_dlsym() {
    let h = dlopen_nw().expect("dlopen");
    let sym = dlsym_nw(h, b"nw_connection_cancel\0");
    assert!(!sym.is_null(), "nw_connection_cancel must resolve on macOS 15+ (A6 verification)");
}

/// Verifies that the AVAILABLE v0.1 nw_* symbols resolve on the build machine.
///
/// On macOS 26+, three original v0.1 symbols are absent (D-20 coverage-gap
/// fallback activates for them at runtime). This test validates the five
/// symbols that ARE available and that our shadow exports are backed by real
/// originals.
///
/// D-20 gap symbols (null on macOS 26, not tested here) are:
///   `nw_connection_create_with_endpoint`, `nw_resolver_create`, `nw_resolver_resolve`.
#[test]
fn all_v1_nw_symbols_resolvable() {
    let h = dlopen_nw().expect("dlopen");
    // Core symbols that must resolve on macOS 26+ per D-12 floor.
    let names: &[&[u8]] = &[
        b"nw_connection_create\0",
        b"nw_connection_start\0",
        b"nw_connection_cancel\0",
        // `nw_endpoint_get_hostname` replaces v0.1's `nw_endpoint_copy_hostname`
        b"nw_endpoint_get_hostname\0",
        // Used in the verdict path to retrieve the endpoint from a connection.
        b"nw_connection_copy_endpoint\0",
    ];
    let mut missing = Vec::new();
    for n in names {
        let p = dlsym_nw(h, n);
        if p.is_null() {
            let name = String::from_utf8_lossy(&n[..n.len()-1]).to_string();
            missing.push(name);
        }
    }
    assert!(missing.is_empty(),
        "missing Network.framework symbols on macOS 26+ build machine: {missing:?} \
         (these should be available per D-12 macOS 15+ floor)");
}

/// Confirms that the D-20 gap symbols are indeed null on macOS 26, so our
/// coverage-gap log path will fire at runtime.
#[test]
fn gap_symbols_are_null_on_macos26() {
    let h = dlopen_nw().expect("dlopen");
    // These three symbols were in the original v0.1 set but are absent on
    // macOS 26.3.1. Confirm null so our init() gap-log is exercised.
    let gap_names: &[&[u8]] = &[
        b"nw_connection_create_with_endpoint\0",
        b"nw_resolver_create\0",
        b"nw_resolver_resolve\0",
    ];
    for n in gap_names {
        let p = dlsym_nw(h, n);
        let name = String::from_utf8_lossy(&n[..n.len()-1]);
        // If a future macOS version adds these back, this test documents the
        // expectation. If it fails: update NW_SYMBOLS in replace_nw.rs.
        assert!(p.is_null(),
            "symbol '{name}' unexpectedly resolves on this macOS version — \
             update replace_nw.rs to activate the shadow export for it");
    }
}
