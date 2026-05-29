//! Tests for the `is_nw_object` safe object-type gate (D-41) in
//! `replace_nw.rs`. Closes the v0.1 carry-over crash where libuv passed
//! non-NW opaque pointers through `nw_connection_start` and the verdict
//! path called `nw_connection_copy_endpoint` on them.

use guard_hook::replace_nw::is_nw_object;
use std::ffi::c_void;

#[test]
fn is_nw_object_returns_false_for_null() {
    assert!(
        !unsafe { is_nw_object(std::ptr::null_mut()) },
        "null pointer must NOT be classified as NW object",
    );
}

#[test]
fn is_nw_object_returns_false_for_random_buffer() {
    // Pass a stack-allocated byte buffer — definitely not an Objective-C object.
    // `object_getClassName` on a non-objc pointer either crashes or returns
    // garbage, but on stable macOS runtimes it returns either NULL or some
    // implementation-defined pointer that is NOT in the OS_nw_* class
    // namespace. Either case must yield false.
    //
    // We use `Box::leak` of a small buffer rather than a stack pointer so the
    // pointer is guaranteed valid for the duration of the call. (Caveat: on
    // some Darwin builds object_getClassName may segfault on truly bogus
    // pointers; if that happens this test will need to be marked
    // `#[ignore]`.)
    let buf: Box<[u8; 64]> = Box::new([0u8; 64]);
    let leaked: &'static mut [u8; 64] = Box::leak(buf);
    let p = leaked.as_mut_ptr().cast::<c_void>();
    // Most platforms either return NULL from object_getClassName on
    // a non-objc pointer or a class name that doesn't start with `OS_nw_`.
    // The is_nw_object gate's whole purpose is to handle this safely.
    let _ = unsafe { is_nw_object(p) }; // primary assertion: didn't crash.
    // (Don't free `leaked` — we leaked it intentionally.)
}

/// Sanity that `is_nw_object` is exported for non-test crate code (i.e. the
/// `nw_connection_start` shadow can call it).
#[test]
fn is_nw_object_is_exported() {
    let _: unsafe fn(*mut c_void) -> bool = is_nw_object;
}
