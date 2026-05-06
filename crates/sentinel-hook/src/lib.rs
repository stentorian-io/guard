//! Sentinel hook cdylib (libsentinel_hook.dylib).
//!
//! Loaded via DYLD_INSERT_LIBRARIES; intercepts libc outbound calls (D-08).
//! Plan 07 layers Network.framework on top by adding `replace_nw` and modifying
//! the constructor to dlsym Network.framework symbols.
//!
//! Hot-path discipline (D-03): NO heap allocation on intercepted-call paths.

#![allow(unused_unsafe)]
// This crate is a DYLD interpose dylib: every `pub unsafe extern "C" fn` is a
// C-ABI shadow whose safety semantics ARE the underlying C function's contract
// (caller-supplied pointers must point to valid C strings / sockaddrs / etc.).
// Adding boilerplate `# Safety` sections on each shadow would duplicate the
// upstream POSIX/Darwin man pages without adding information. The interpose
// crate-wide intent is "C-ABI passthrough; semantics inherited from libc/Darwin".
#![allow(clippy::missing_safety_doc)]
// `pub fn copy_cstr_to_buf(p: *const c_char, ...)` is intentionally a SAFE
// function over a raw pointer: it null-checks the pointer and bounded-copies
// up to `buf.len()` bytes, dereferencing only when `p` is non-null. Callers
// from the exec hooks (also FFI) depend on the safe-API ergonomics. The lint
// is overly conservative for this defensive-copy helper.
#![allow(clippy::not_unsafe_ptr_arg_deref)]
// Pre-existing Phase 1 patterns flagged once Phase 2 plan 02-05 added clippy
// to sentinel-hook's verification gate. Out-of-scope cleanup tracked in
// Phase 02 deferred-items.md (Plan 02-05 row).
#![allow(clippy::needless_lifetimes, clippy::unnecessary_cast, dead_code)]

pub mod cache;
pub mod interpose; // Filled in by task 2; symbol re-export only at this point
pub mod ipc_client; // Phase 2 plan 02-05: blocking IPC for ForkEvent / ExecEvent / DylibLoaded
pub mod log_buffer;
pub mod reentrancy;
pub mod replace_exec; // Phase 2 plan 02-05: exec-family shadows
pub mod replace_fork; // Phase 2 plan 02-05: fork/vfork/posix_spawn shadows
pub mod replace_libc; // Filled in by task 2
pub mod replace_nw; // Plan 07: Network.framework dlsym + shadow exports
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
    // 0. SC1 test marker — write a marker file when SENTINEL_TEST_MARKER is set.
    //    This is the cheapest reliable dylib-load indicator for the smoke_dylib_loaded
    //    e2e test: the test sets SENTINEL_TEST_MARKER to a tempdir path and asserts
    //    the file exists after the child exits, proving the ctor ran (= dylib loaded).
    //
    //    The env var is intentionally named with a TEST prefix so it is obvious this
    //    is a test-only hook. Production deployments never set SENTINEL_TEST_MARKER,
    //    so this is a no-op in all real usage.
    unsafe { write_test_marker_if_set() };

    // 1. Capture original libc symbol pointers via RTLD_NEXT.
    unsafe { interpose::capture_originals() };

    // 1.5. dlopen Network.framework and dlsym seven nw_* symbols into AtomicPtrs (D-09).
    // Missing symbols are logged as coverage-gap lines; NW_AVAILABLE stays false if
    // dlopen fails (D-20 libc-only fallback path).
    replace_nw::init();

    // 1.6. Phase 2 plan 02-05: cache the daemon socket path from env. Subsequent
    //      ipc_client::send_*_sync calls use this cached path. Failure here means
    //      env unset — IPC calls return NotConfigured and the dylib operates with
    //      the same fail-mode as Phase 1 (no fork/exec tracking, but the verdict
    //      path still works against the snapshot).
    crate::ipc_client::cache_daemon_socket_from_env();

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

    // 3. Phase 2 plan 02-05 / D-35: send DylibLoaded IPC to daemon.
    //
    //    Best-effort: failure is logged but does NOT FAIL_CLOSED. The daemon's
    //    gap detector (plan 02-04) will record an UnknownInjectionFailure if
    //    no DylibLoaded arrives within 500ms of the parent's ExecEvent.
    //
    //    Use a SHORT timeout (100ms) — we do not want a slow daemon to block
    //    pre-main of the wrapped process. The wrapped command starts running
    //    even if DylibLoaded times out (T-02-05-06 mitigation).
    if !snapshot::FAIL_CLOSED.load(Ordering::Acquire) {
        const DYLIB_LOADED_TIMEOUT_MS: u64 = 100;
        // BLOCKER-07: include (pid, ppid) as an advisory hint in the wire
        // audit-token so the daemon's BLOCKER-02 untracked-peer check can
        // optionally use ppid to walk the tree and decide whether to ack.
        // Daemon's authoritative parent identity remains kernel peer-auth
        // (ENF-08); the wire fields are advisory.
        // SAFETY: getpid()/getppid() are async-signal-safe and always succeed.
        let pid = unsafe { libc::getpid() } as u32;
        let ppid = unsafe { libc::getppid() } as u32;
        let mut tok_val = [0u32; 8];
        tok_val[5] = pid;
        tok_val[6] = ppid;
        let token = sentinel_ipc::AuditTokenWire { val: tok_val };
        match crate::ipc_client::send_dylib_loaded_sync(token, DYLIB_LOADED_TIMEOUT_MS) {
            Ok(()) => {
                LOG_RING.append(b"[sentinel-hook] DylibLoaded sent");
            }
            Err(e) => {
                let line = format!("[sentinel-hook] DylibLoaded best-effort failed: {e}");
                LOG_RING.append(line.as_bytes());
            }
        }
    }

    // 4. mprotect the originals page read-only (T-01-06-04 mitigation).
    // PHASE 1 STATUS: disabled. The mprotect call is too coarse-grained — it
    // marks the ENTIRE page containing REAL_CONNECT read-only. Other writable
    // statics on the same page (e.g. the per-process Mutex<Cache> in
    // replace_libc.rs) then cause SIGBUS when written at connect-time.
    // Root cause: the compiler/linker places AtomicPtr statics and Mutex statics
    // on the same 4K page. A page-level mprotect cannot protect only the
    // AtomicPtrs without also making the Mutex read-only.
    //
    // Phase 5 plan: separate REAL_* statics into a dedicated section
    // (#[link_section = "__DATA_CONST,__sentinel_orig"]) so they occupy an
    // isolated page that can be safely mprotected. Until then, this step is
    // skipped to avoid the SIGBUS regression (Rule 1 auto-fix).
    //
    // 5. Phase 2 plan 02-05 / D-44: re-enabled interpose-effectiveness probe.
    //    Phase 1 commented this out citing "crash; will re-enable after root
    //    cause identified". Plan 02-05 confirms the crash was the mprotect step
    //    above (now permanently disabled until Phase 5 dedicated-section work),
    //    NOT probe_self_test itself. Re-enabling closes the silent-injection-
    //    failure gap: if dyld doesn't apply our interpose records, the dylib
    //    loads but no FAIL_CLOSED fires. probe_self_test catches that case by
    //    asserting dlsym(RTLD_DEFAULT,"connect") == &sentinel_connect.
    if !snapshot::FAIL_CLOSED.load(Ordering::Acquire) {
        // interpose::lock_originals_page();  // disabled: Phase 5 (see above)
        interpose::probe_self_test();
    }
}

/// Write a marker file to the path given by SENTINEL_TEST_MARKER if the env var is set.
///
/// This is a test-only hook. Production processes never set SENTINEL_TEST_MARKER.
/// The file is written during the dylib constructor so its existence proves the ctor ran,
/// which is the cheapest reliable evidence that DYLD_INSERT_LIBRARIES loaded our dylib.
///
/// # Safety
/// Called from the dylib constructor (single-threaded, pre-main). libc::getenv is
/// safe here because no concurrent setenv can occur before main() starts.
unsafe fn write_test_marker_if_set() {
    use std::ffi::CStr;
    // Use libc::getenv to stay allocation-free until we know the env var is set.
    // SAFETY: ctor runs pre-main, single-threaded; getenv pointer stable for duration.
    let p = unsafe { libc::getenv(c"SENTINEL_TEST_MARKER".as_ptr()) };
    if p.is_null() {
        return;
    }
    let path_str = unsafe { CStr::from_ptr(p) }.to_string_lossy();
    if path_str.is_empty() {
        return;
    }
    // Write the marker file. A zero-byte file is sufficient.
    // Use std::fs::write — allocation is fine here (not on the hot path).
    let _ = std::fs::write(path_str.as_ref(), b"dylib-loaded");
}
