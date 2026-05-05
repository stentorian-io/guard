//! Sentinel hook cdylib (libsentinel_hook.dylib).
//!
//! Loaded via DYLD_INSERT_LIBRARIES; intercepts libc outbound calls (D-08).
//! Plan 07 layers Network.framework on top by adding `replace_nw` and modifying
//! the constructor to dlsym Network.framework symbols.
//!
//! Hot-path discipline (D-03): NO heap allocation on intercepted-call paths.

#![allow(unused_unsafe)]

pub mod cache;
pub mod interpose; // Filled in by task 2; symbol re-export only at this point
pub mod log_buffer;
pub mod reentrancy;
pub mod replace_libc; // Filled in by task 2
pub mod snapshot;

use core::sync::atomic::{AtomicBool, Ordering};
use log_buffer::LOG_RING;

/// Set by the constructor; read by replacement functions on the hot path.
/// When true, every match is Deny (D-14 fail-closed).
pub static FAIL_CLOSED: &AtomicBool = &snapshot::FAIL_CLOSED;

/// Process-global mutable allowlist entries — populated at ctor time, immutable thereafter.
/// Wrapped in OnceLock so the hot path only sees a fully-initialized value.
pub static ALLOWLIST: std::sync::OnceLock<Vec<sentinel_core::AllowlistEntry>> =
    std::sync::OnceLock::new();

/// Constructor — runs when the library is loaded (both as dylib and in test rlib linkage).
/// In non-dylib contexts (tests), SENTINEL_SNAPSHOT_MANIFEST is not set, so step 2
/// sets FAIL_CLOSED and returns cleanly. Steps 3 and 4 are skipped via compile-time cfg.
#[ctor::ctor(unsafe)]
unsafe fn sentinel_hook_init() {
    // 1. Capture original libc symbol pointers via RTLD_NEXT.
    unsafe { interpose::capture_originals() };

    // 2. Load snapshot (manifest + digest verify + mmap).
    match snapshot::load_from_env() {
        Ok(loaded) => {
            let _ = ALLOWLIST.set(loaded.entries);
            // Log success line (constructor path: alloc OK).
            let line = format!(
                "[sentinel-hook] snapshot loaded schema_version={} path={}",
                loaded.schema_version,
                loaded.snapshot_path.display()
            );
            LOG_RING.append(line.as_bytes());
        }
        Err(e) => {
            snapshot::FAIL_CLOSED.store(true, Ordering::Release);
            let line = format!(
                "[sentinel-hook] FAIL_CLOSED — snapshot load failed: {:?}",
                e
            );
            LOG_RING.append(line.as_bytes());
        }
    }

    // 3. mprotect the originals page read-only (T-01-06-04 mitigation).
    // This step is ONLY safe in the actual DYLD injection context. In test binaries,
    // mprotecting the REAL_* statics page causes SIGBUS when Rust's test harness
    // writes to statics on that same page during test execution.
    // We detect dylib context by checking if SENTINEL_SNAPSHOT_MANIFEST was set
    // (which the CLI sets before invoking the wrapped process). If it wasn't set,
    // we're in a test binary and skip the mprotect.
    if !snapshot::FAIL_CLOSED.load(Ordering::Acquire) {
        interpose::lock_originals_page();

        // 4. ISS-12 remediation — interpose-effectiveness probe.
        // Only meaningful in dylib injection context where sentinel_connect should be
        // the active connect symbol.
        interpose::probe_self_test();
    }
}
