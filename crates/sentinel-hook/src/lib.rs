//! Sentinel hook cdylib (libsentinel_hook.dylib).
//! Loaded via DYLD_INSERT_LIBRARIES; intercepts libc + Network.framework outbound calls.
//! Plan 06 fills in the interpose statics + replacement functions.
//! Plan 07 adds Network.framework dlsym shadow.
//!
//! Hot-path discipline (D-03): NO heap allocation on intercepted-call paths.

#![allow(unused_imports)]

// Plan 06 adds: pub mod interpose; pub mod replace_libc;
//               pub mod snapshot; pub mod cache; pub mod reentrancy;
// Plan 07 adds: pub mod replace_nw;

// Stub constructor so the cdylib has at least one ctor symbol from day one
// (helps verify the build in cargo check).
#[ctor::ctor(unsafe)]
fn _sentinel_hook_skeleton_ctor() {
    // Intentionally empty. Plan 06 replaces this with the real ctor.
}
