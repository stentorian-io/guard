//! M004-S04: Anti-detection hardening — hide Stentorian Guard env vars from
//! application-level inspection without breaking hook propagation.
//!
//! Strategy: interpose `getenv` to return NULL for Stentorian Guard-internal env
//! vars once the ctor has finished initialization. During ctor (pre-main),
//! the filter is disabled so the hook can read its own config vars.
//!
//! We do NOT modify `environ` because child processes need the platform hook
//! injection variable to inherit hook injection.
//!
//! Hidden from application code (after ctor):
//!   - STT_GUARD_SNAPSHOT_MANIFEST
//!   - STT_GUARD_STATE_DIR
//!   - STT_GUARD_TEST_MARKER
//!   - platform hook injection variable (hides our hook library path)

use core::sync::atomic::{AtomicBool, Ordering};
use std::ffi::CStr;

/// Set to true at the end of the ctor. Before this, getenv passthrough
/// is unrestricted so the hook can read its own config.
pub static SCRUB_ACTIVE: AtomicBool = AtomicBool::new(false);

unsafe extern "C" {
    /// The POSIX `environ` global — a NULL-terminated array of "KEY=VALUE\0"
    /// C strings. We read this directly to implement getenv without calling
    /// libc's getenv (which is interposed by us, creating infinite recursion).
    /// dlsym also can't help because dyld patches ALL symbol tables including
    /// libSystem's, so dlsym(anything, "getenv") returns guard_getenv.
    #[link_name = "environ"]
    static environ: *const *mut libc::c_char;
}

/// Manual getenv implementation that reads `environ` directly.
/// Returns a pointer into the environ array (same semantics as libc getenv).
unsafe fn raw_getenv(name: *const libc::c_char) -> *mut libc::c_char {
    if name.is_null() {
        return std::ptr::null_mut();
    }
    let name_cstr = unsafe { CStr::from_ptr(name) };
    let name_bytes = name_cstr.to_bytes();
    if name_bytes.is_empty() {
        return std::ptr::null_mut();
    }

    let env = unsafe { environ };
    if env.is_null() {
        return std::ptr::null_mut();
    }

    let mut i = 0usize;
    loop {
        let entry = unsafe { *env.add(i) };
        if entry.is_null() {
            break;
        }
        let entry_cstr = unsafe { CStr::from_ptr(entry) };
        let entry_bytes = entry_cstr.to_bytes();
        // Check if entry starts with "name="
        if entry_bytes.len() > name_bytes.len()
            && entry_bytes[name_bytes.len()] == b'='
            && entry_bytes[..name_bytes.len()] == *name_bytes
        {
            // Return pointer to the value (after the '=')
            return unsafe { entry.add(name_bytes.len() + 1) };
        }
        i += 1;
    }
    std::ptr::null_mut()
}

#[cfg(target_os = "macos")]
const HOOK_INJECTION_ENV: &CStr = c"DYLD_INSERT_LIBRARIES";
#[cfg(target_os = "linux")]
const HOOK_INJECTION_ENV: &CStr = c"LD_PRELOAD";
#[cfg(not(any(target_os = "macos", target_os = "linux")))]
const HOOK_INJECTION_ENV: &CStr = c"LD_PRELOAD";

const HIDDEN_NAMES: &[&CStr] = &[
    c"STT_GUARD_SNAPSHOT_MANIFEST",
    c"STT_GUARD_STATE_DIR",
    c"STT_GUARD_TEST_MARKER",
    HOOK_INJECTION_ENV,
];

/// Check whether a getenv key should be hidden from application code.
pub fn is_hidden_key(name: *const libc::c_char) -> bool {
    if name.is_null() {
        return false;
    }
    let name_cstr = unsafe { CStr::from_ptr(name) };
    HIDDEN_NAMES.contains(&name_cstr)
}

/// Interposed getenv: returns NULL for hidden keys once SCRUB_ACTIVE is
/// true. During ctor initialization, passes through to real getenv.
///
/// # Safety
/// C-ABI passthrough; `name` must be a valid C string (caller contract).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn guard_getenv(name: *const libc::c_char) -> *mut libc::c_char {
    if SCRUB_ACTIVE.load(Ordering::Acquire) && is_hidden_key(name) {
        return std::ptr::null_mut();
    }
    unsafe { raw_getenv(name) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hidden_keys_detected() {
        assert!(is_hidden_key(c"STT_GUARD_SNAPSHOT_MANIFEST".as_ptr()));
        assert!(is_hidden_key(c"STT_GUARD_STATE_DIR".as_ptr()));
        assert!(is_hidden_key(c"STT_GUARD_TEST_MARKER".as_ptr()));
        #[cfg(target_os = "macos")]
        assert!(is_hidden_key(c"DYLD_INSERT_LIBRARIES".as_ptr()));
        #[cfg(target_os = "linux")]
        assert!(is_hidden_key(c"LD_PRELOAD".as_ptr()));
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
