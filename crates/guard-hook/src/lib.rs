//! Stentorian Guard hook cdylib (stt-guard-hook.dylib).
//!
//! Loaded via `DYLD_INSERT_LIBRARIES`; intercepts libc outbound calls (D-08).
//! v0.1 layers Network.framework on top by adding `replace_nw` and modifying
//! the constructor to dlsym Network.framework symbols.
//!
//! Hot-path discipline (D-03): NO heap allocation on intercepted-call paths.

pub mod cache;
pub mod env_scrub; // M004-S04: scrub STT_GUARD_*/DYLD_INSERT_LIBRARIES from environ
pub mod envp; // v0.2: pre-spawn envp inspector (TREE-06)
pub mod exec_policy; // M003-S02: hardened-runtime exec blocking policy
pub mod fd_class; // M003-S01-T03: thread-local fd classification bitmap for write/writev hooks
pub mod interpose; // Filled in by task 2; symbol re-export only at this point
pub mod ipc_client; // v0.2: blocking IPC for ForkEvent / ExecEvent / DylibLoaded
pub mod log_buffer;
pub mod macho_flags; // M003-S02: Mach-O code-signing flag parser for hardened-runtime exec blocking
pub mod macho_scan; // Compatibility re-export for scanner types and entry points
pub mod persistence_paths; // M003-S04: persistence-path classifier for open/openat monitoring
pub mod pm_env_filter; // quick-260508-et9 (BLOCKER #1): dylib-side pm_env capture
pub mod raw_syscall; // M003-S01: direct kernel syscall wrappers for hook call-through
pub mod reentrancy;
pub mod replace_exec; // v0.2: exec-family shadows
pub mod replace_fork; // v0.2: fork/vfork/posix_spawn shadows
pub mod replace_libc; // Filled in by task 2
pub mod replace_nw; // v0.1: Network.framework dlsym + shadow exports
pub mod replace_open; // M003-S04: open/openat interpose for persistence monitoring
pub mod scanner; // Issue #59: OS/format-specific exec-target scanner boundary
pub mod self_check; // M004-S03: hook binary self-integrity verification
pub mod snapshot;

use core::sync::atomic::{AtomicBool, Ordering};
use log_buffer::LOG_RING;

/// Set by the constructor; read by replacement functions on the hot path.
/// When true, every match is Deny (D-14 fail-closed).
pub static FAIL_CLOSED: &AtomicBool = &snapshot::FAIL_CLOSED;

/// Process-global mutable allowlist entries — populated at ctor time, immutable thereafter.
/// Wrapped in `OnceLock` so the hot path only sees a fully-initialized value.
pub static ALLOWLIST: std::sync::OnceLock<Vec<guard_core::AllowlistEntry>> =
    std::sync::OnceLock::new();

/// Test-only helper: call `replace_libc::decide_for_sockaddr` with a temporary ALLOWLIST
/// override so integration tests can verify the full Resolve-IPC → cache → `evaluate_policy`
/// chain without running the ctor or needing a real snapshot.
///
/// Exposed as pub because integration tests in `tests/` cannot see crate-private items.
///
/// # Safety
///
/// `addr` must be null or point to a valid sockaddr of at least `addrlen`
/// bytes.
pub unsafe fn test_decide_for_sockaddr(
    entries: Vec<guard_core::AllowlistEntry>,
    addr: *const libc::sockaddr,
    addrlen: libc::socklen_t,
) -> guard_core::Verdict {
    // Temporarily override the ALLOWLIST so decide_for_sockaddr sees `entries`.
    // If ALLOWLIST is already set (from a prior test), we skip the set (OnceLock can only be set once).
    // Tests should avoid relying on a pre-set ALLOWLIST from the ctor.
    let _ = ALLOWLIST.set(entries);
    // Ensure FAIL_CLOSED is false so entries_or_deny() returns Some.
    snapshot::FAIL_CLOSED.store(false, core::sync::atomic::Ordering::Release);
    // SAFETY: caller provides a valid sockaddr pointer with matching addrlen.
    let (verdict, _source) =
        unsafe { crate::replace_libc::decide_for_sockaddr_for_test(addr, addrlen) };
    verdict
}

/// Constructor — runs when the library is loaded (both as dylib and in test rlib linkage).
/// In non-dylib contexts (tests), STT_GUARD_SNAPSHOT_MANIFEST is not set, so step 2
/// sets FAIL_CLOSED and returns cleanly. Steps 3 and 4 are skipped via compile-time cfg.
#[ctor::ctor(unsafe)]
unsafe fn guard_hook_init() {
    // 0. SC1 test marker — write a marker file when STT_GUARD_TEST_MARKER is set.
    //    This is the cheapest reliable dylib-load indicator for the smoke_dylib_loaded
    //    e2e test: the test sets STT_GUARD_TEST_MARKER to a tempdir path and asserts
    //    the file exists after the child exits, proving the ctor ran (= dylib loaded).
    //
    //    The env var is intentionally named with a TEST prefix so it is obvious this
    //    is a test-only hook. Production deployments never set STT_GUARD_TEST_MARKER,
    //    so this is a no-op in all real usage.
    unsafe { write_test_marker_if_set() };

    // 1. Capture original libc symbol pointers via RTLD_NEXT.
    unsafe { interpose::capture_originals() };

    // 1.5. Network.framework init deferred to first NW shadow call to avoid
    // dispatch_once reentrancy deadlock on macOS 26+ (dlopen during ctor
    // triggers CoreFoundation initialization which re-enters dispatch_once).
    // replace_nw::ensure_init() is called lazily from each NW shadow export.

    // 1.6. v0.2: cache the daemon socket path from env. Subsequent
    //      ipc_client::send_*_sync calls use this cached path. Failure here means
    //      env unset — IPC calls return NotConfigured and the dylib operates with
    //      the same fail-mode as v0.1 (no fork/exec tracking, but the verdict
    //      path still works against the snapshot).
    crate::ipc_client::cache_daemon_socket_path();

    // 2. Load snapshot (manifest + digest verify + mmap).
    match snapshot::load_from_env() {
        Ok(loaded) => {
            let _ = ALLOWLIST.set(loaded.entries);
            // Log success line (constructor path: alloc OK).
            let line = format!(
                "[guard-hook] snapshot loaded schema_version={} path={}",
                loaded.schema_version,
                loaded.snapshot_path.display()
            );
            LOG_RING.append(line.as_bytes());
        }
        Err(e) => {
            snapshot::FAIL_CLOSED.store(true, Ordering::Release);
            let line = format!("[guard-hook] FAIL_CLOSED — snapshot load failed: {e:?}");
            LOG_RING.append(line.as_bytes());
        }
    }

    // 2.5. M004-S03: verify hook binary integrity against stored hash.
    //      Fail-closed if the hash file exists and doesn't match.
    {
        let state_dir = crate::snapshot::well_known_state_dir();
        if let Err(e) = crate::self_check::verify(&state_dir) {
            snapshot::FAIL_CLOSED.store(true, Ordering::Release);
            let line = format!("[guard-hook] FAIL_CLOSED — self-check failed: {e:?}");
            LOG_RING.append(line.as_bytes());
        }
    }

    // 3. v0.2 / D-35: send DylibLoaded IPC to daemon.
    //
    //    Best-effort: failure is logged but does NOT FAIL_CLOSED. The daemon's
    //    gap detector will record an UnknownInjectionFailure if
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
        let pid = u32::try_from(unsafe { libc::getpid() }).unwrap_or(0);
        let ppid = u32::try_from(unsafe { libc::getppid() }).unwrap_or(0);
        let mut tok_val = [0u32; 8];
        tok_val[5] = pid;
        tok_val[6] = ppid;
        let token = guard_ipc::AuditTokenWire { val: tok_val };
        match crate::ipc_client::send_dylib_loaded_sync(token, DYLIB_LOADED_TIMEOUT_MS) {
            Ok(()) => {
                LOG_RING.append(b"[guard-hook] DylibLoaded sent");
            }
            Err(e) => {
                let line = format!("[guard-hook] DylibLoaded best-effort failed: {e}");
                LOG_RING.append(line.as_bytes());
            }
        }
    }

    // 4. mprotect the originals page read-only (T-01-06-04 mitigation).
    // v0.1 STATUS: disabled. The mprotect call is too coarse-grained — it
    // marks the ENTIRE page containing REAL_CONNECT read-only. Other writable
    // statics on the same page (e.g. the per-process Mutex<Cache> in
    // replace_libc.rs) then cause SIGBUS when written at connect-time.
    // Root cause: the compiler/linker places AtomicPtr statics and Mutex statics
    // on the same 4K page. A page-level mprotect cannot protect only the
    // AtomicPtrs without also making the Mutex read-only.
    //
    // v0.5 plan: separate REAL_* statics into a dedicated section
    // (#[link_section = "__DATA_CONST,__guard_orig"]) so they occupy an
    // isolated page that can be safely mprotected. Until then, this step is
    // skipped to avoid the SIGBUS regression (Rule 1 auto-fix).
    //
    // 5. v0.2 / D-44: re-enabled interpose-effectiveness probe.
    //    v0.1 commented this out citing "crash; will re-enable after root
    //    cause identified". v0.2 confirms the crash was the mprotect step
    //    above (now permanently disabled until v0.5 dedicated-section work),
    //    NOT probe_self_test itself. Re-enabling closes the silent-injection-
    //    failure gap: if dyld doesn't apply our interpose records, the dylib
    //    loads but no FAIL_CLOSED fires. probe_self_test catches that case by
    //    asserting dlsym(RTLD_DEFAULT,"connect") == &guard_connect.
    if !snapshot::FAIL_CLOSED.load(Ordering::Acquire) {
        // interpose::lock_originals_page();  // disabled: v0.5 (see above)
        interpose::probe_self_test();
    }

    // 6. M004-S04: activate getenv scrubbing now that all config vars are cached.
    //    Application code calling getenv("STT_GUARD_*") or
    //    getenv("DYLD_INSERT_LIBRARIES") will get NULL from this point on.
    //    environ is left intact so child processes inherit hook injection.
    env_scrub::SCRUB_ACTIVE.store(true, Ordering::Release);
}

/// Write a marker file to the path given by `STT_GUARD_TEST_MARKER` if the env var is set.
///
/// This is a test-only hook. Production processes never set `STT_GUARD_TEST_MARKER`.
/// The file is written during the dylib constructor so its existence proves the ctor ran,
/// which is the cheapest reliable evidence that `DYLD_INSERT_LIBRARIES` loaded our dylib.
///
/// # Safety
/// Called from the dylib constructor (single-threaded, pre-main). `libc::getenv` is
/// safe here because no concurrent setenv can occur before `main()` starts.
unsafe fn write_test_marker_if_set() {
    use std::ffi::CStr;
    // Use libc::getenv to stay allocation-free until we know the env var is set.
    // SAFETY: ctor runs pre-main, single-threaded; getenv pointer stable for duration.
    let p = unsafe { libc::getenv(c"STT_GUARD_TEST_MARKER".as_ptr()) };
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
