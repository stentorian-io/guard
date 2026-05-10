//! M004-S04: Anti-detection hardening — hide Sentinel env vars from
//! application-level inspection without breaking hook propagation.
//!
//! Strategy: interpose `getenv` to return NULL for Sentinel-internal env
//! vars once the ctor has finished initialization. During ctor (pre-main),
//! the filter is disabled so the hook can read its own config vars.
//!
//! We do NOT modify `environ` because child processes need
//! `DYLD_INSERT_LIBRARIES` to inherit hook injection.
//!
//! Hidden from application code (after ctor):
//!   - SENTINEL_SNAPSHOT_MANIFEST
//!   - SENTINEL_DAEMON_SOCKET
//!   - SENTINEL_STATE_DIR
//!   - SENTINEL_TEST_MARKER
//!   - DYLD_INSERT_LIBRARIES (hides our dylib path)

use core::sync::atomic::{AtomicBool, Ordering};
use std::ffi::CStr;

/// Set to true at the end of the ctor. Before this, getenv passthrough
/// is unrestricted so the hook can read its own config.
pub static SCRUB_ACTIVE: AtomicBool = AtomicBool::new(false);

const HIDDEN_NAMES: &[&CStr] = &[
    c"SENTINEL_SNAPSHOT_MANIFEST",
    c"SENTINEL_DAEMON_SOCKET",
    c"SENTINEL_STATE_DIR",
    c"SENTINEL_TEST_MARKER",
    c"DYLD_INSERT_LIBRARIES",
];

/// Check whether a getenv key should be hidden from application code.
pub fn is_hidden_key(name: *const libc::c_char) -> bool {
    if name.is_null() {
        return false;
    }
    let name_cstr = unsafe { CStr::from_ptr(name) };
    HIDDEN_NAMES.iter().any(|h| name_cstr == *h)
}

/// Interposed getenv: returns NULL for hidden keys once SCRUB_ACTIVE is
/// true. During ctor initialization, passes through to real getenv.
///
/// # Safety
/// C-ABI passthrough; `name` must be a valid C string (caller contract).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sentinel_getenv(name: *const libc::c_char) -> *mut libc::c_char {
    if SCRUB_ACTIVE.load(Ordering::Acquire) && is_hidden_key(name) {
        return std::ptr::null_mut();
    }
    let real = unsafe { libc::dlsym(libc::RTLD_NEXT, c"getenv".as_ptr()) };
    if real.is_null() {
        return std::ptr::null_mut();
    }
    let real_fn: unsafe extern "C" fn(*const libc::c_char) -> *mut libc::c_char =
        unsafe { std::mem::transmute(real) };
    unsafe { real_fn(name) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hidden_keys_detected() {
        assert!(is_hidden_key(c"SENTINEL_SNAPSHOT_MANIFEST".as_ptr()));
        assert!(is_hidden_key(c"SENTINEL_DAEMON_SOCKET".as_ptr()));
        assert!(is_hidden_key(c"SENTINEL_STATE_DIR".as_ptr()));
        assert!(is_hidden_key(c"SENTINEL_TEST_MARKER".as_ptr()));
        assert!(is_hidden_key(c"DYLD_INSERT_LIBRARIES".as_ptr()));
    }

    #[test]
    fn non_hidden_keys_pass_through() {
        assert!(!is_hidden_key(c"HOME".as_ptr()));
        assert!(!is_hidden_key(c"PATH".as_ptr()));
        assert!(!is_hidden_key(c"npm_config_registry".as_ptr()));
        assert!(!is_hidden_key(std::ptr::null()));
    }

    #[test]
    fn scrub_active_flag_starts_false() {
        // In tests, ctor may or may not have run, but the default is false.
        // We just verify the flag type is correct.
        let _ = SCRUB_ACTIVE.load(Ordering::Relaxed);
    }
}
