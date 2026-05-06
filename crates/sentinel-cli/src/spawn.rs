//! posix_spawnp wrapper that injects DYLD_INSERT_LIBRARIES,
//! SENTINEL_SNAPSHOT_MANIFEST, and SENTINEL_DAEMON_SOCKET into the child's envp.
//!
//! Pattern: .planning/phases/01-foundations-hook-hello-world/01-RESEARCH.md
//! lines 671-739 (Example 1).
//!
//! Phase 2 plan 02-06b: SENTINEL_DAEMON_SOCKET added so the dylib's
//! `cache_daemon_socket_from_env` (plan 02-05) finds the daemon socket and
//! can send ForkEvent / ExecEvent / DylibLoaded events.

use std::ffi::{CString, OsStr};
use std::os::unix::ffi::OsStrExt;
use std::path::Path;

const ENV_DYLD: &str = "DYLD_INSERT_LIBRARIES";
const ENV_MANIFEST: &str = "SENTINEL_SNAPSHOT_MANIFEST";
const ENV_DAEMON_SOCKET: &str = "SENTINEL_DAEMON_SOCKET";

pub fn spawn_wrapped(
    program: &Path,
    args: &[&OsStr],
    dylib_path: &Path,
    manifest_path: &Path,
    socket_path: &Path,
) -> std::io::Result<libc::pid_t> {
    // Build envp: inherit current environment minus the three we manage.
    let mut env: Vec<CString> = std::env::vars_os()
        .filter_map(|(k, v)| {
            let k_bytes = k.as_bytes();
            // Strip our managed vars — we'll re-add them with proper values below.
            if k_bytes == ENV_DYLD.as_bytes()
                || k_bytes == ENV_MANIFEST.as_bytes()
                || k_bytes == ENV_DAEMON_SOCKET.as_bytes()
            {
                return None;
            }
            let mut s = k_bytes.to_vec();
            s.push(b'=');
            s.extend_from_slice(v.as_bytes());
            // Skip env vars with embedded NUL bytes (should not exist but be defensive).
            CString::new(s).ok()
        })
        .collect();

    // DYLD_INSERT_LIBRARIES: prepend our dylib so dyld processes it first;
    // append any prior value (separated by ':') so other interposers still load.
    // T-01-08-01: our dylib is left-most so we get first chance at interpose records.
    let prior = std::env::var_os(ENV_DYLD).unwrap_or_default();
    let mut dyld_value = dylib_path.as_os_str().as_bytes().to_vec();
    if !prior.is_empty() {
        dyld_value.push(b':');
        dyld_value.extend_from_slice(prior.as_bytes());
    }
    let mut entry = ENV_DYLD.as_bytes().to_vec();
    entry.push(b'=');
    entry.extend_from_slice(&dyld_value);
    env.push(
        CString::new(entry)
            .map_err(|e| std::io::Error::other(format!("DYLD env contains NUL: {e}")))?,
    );

    // SENTINEL_SNAPSHOT_MANIFEST: absolute path for the dylib to read at ctor time.
    let mut entry2 = ENV_MANIFEST.as_bytes().to_vec();
    entry2.push(b'=');
    entry2.extend_from_slice(manifest_path.as_os_str().as_bytes());
    env.push(
        CString::new(entry2)
            .map_err(|e| std::io::Error::other(format!("MANIFEST env contains NUL: {e}")))?,
    );

    // SENTINEL_DAEMON_SOCKET: absolute path the dylib uses to talk back to the
    // daemon (plan 02-05's ipc_client::cache_daemon_socket_from_env reads this
    // at ctor time). Without it the dylib's send_*_sync calls return
    // NotConfigured and the fork/exec/dylib_loaded events never reach the
    // daemon — Phase 2 IPC is a no-op.
    let mut entry3 = ENV_DAEMON_SOCKET.as_bytes().to_vec();
    entry3.push(b'=');
    entry3.extend_from_slice(socket_path.as_os_str().as_bytes());
    env.push(
        CString::new(entry3).map_err(|e| {
            std::io::Error::other(format!("DAEMON_SOCKET env contains NUL: {e}"))
        })?,
    );

    // Build argv[0] = program name.
    let prog_c = CString::new(program.as_os_str().as_bytes())
        .map_err(|e| std::io::Error::other(format!("program path contains NUL: {e}")))?;
    let mut argv: Vec<CString> = Vec::with_capacity(args.len() + 1);
    argv.push(prog_c.clone());
    for a in args {
        argv.push(
            CString::new(a.as_bytes())
                .map_err(|e| std::io::Error::other(format!("argument contains NUL: {e}")))?,
        );
    }

    // Build null-terminated pointer arrays for posix_spawnp.
    let mut argv_ptrs: Vec<*mut libc::c_char> =
        argv.iter().map(|c| c.as_ptr() as *mut libc::c_char).collect();
    argv_ptrs.push(std::ptr::null_mut());

    let mut envp_ptrs: Vec<*mut libc::c_char> =
        env.iter().map(|c| c.as_ptr() as *mut libc::c_char).collect();
    envp_ptrs.push(std::ptr::null_mut());

    let mut pid: libc::pid_t = 0;
    let rc = unsafe {
        libc::posix_spawnp(
            &mut pid,
            prog_c.as_ptr(),
            std::ptr::null(), // file_actions: none
            std::ptr::null(), // attrp: none (default attrs)
            argv_ptrs.as_ptr(),
            envp_ptrs.as_ptr(),
        )
    };
    if rc != 0 {
        return Err(std::io::Error::from_raw_os_error(rc));
    }
    Ok(pid)
}
