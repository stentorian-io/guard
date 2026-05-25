//! posix_spawnp wrapper that injects the platform hook variable and
//! STT_GUARD_SNAPSHOT_MANIFEST into the child's envp. The hook derives the
//! daemon socket path from STT_GUARD_STATE_DIR at ctor time.

use std::ffi::OsString;
use std::ffi::{CString, OsStr};
use std::os::unix::ffi::OsStrExt;
use std::path::Path;

use guard_core::paths::{
    ENV_HOOK_INJECTION, ENV_SNAPSHOT_MANIFEST as ENV_MANIFEST, ENV_STATE_DIR as ENV_STATE,
};

const ENV_DAEMON_SOCKET: &str = "STT_GUARD_DAEMON_SOCKET";
const ENV_TRUSTED_SIGNERS_MANIFEST: &str = "STT_GUARD_TRUSTED_SIGNERS_MANIFEST";
const ENV_ALLOW_TEST_SIGNER: &str = "STT_GUARD_ALLOW_TEST_SIGNER";

pub fn spawn_wrapped(
    program: &Path,
    args: &[&OsStr],
    dylib_path: &Path,
    manifest_path: &Path,
) -> std::io::Result<libc::pid_t> {
    // Build envp: inherit current environment minus the vars we manage.
    let mut env: Vec<CString> = std::env::vars_os()
        .filter_map(|(k, v)| {
            let k_bytes = k.as_bytes();
            if k_bytes == ENV_HOOK_INJECTION.as_bytes()
                || k_bytes == ENV_MANIFEST.as_bytes()
                || k_bytes == ENV_STATE.as_bytes()
                || k_bytes == ENV_DAEMON_SOCKET.as_bytes()
                || k_bytes == ENV_TRUSTED_SIGNERS_MANIFEST.as_bytes()
                || k_bytes == ENV_ALLOW_TEST_SIGNER.as_bytes()
            {
                return None;
            }
            let mut s = k_bytes.to_vec();
            s.push(b'=');
            s.extend_from_slice(v.as_bytes());
            CString::new(s).ok()
        })
        .collect();

    // Prepend our hook library so the platform dynamic loader processes it first.
    let prior = std::env::var_os(ENV_HOOK_INJECTION).unwrap_or_default();
    let mut injection_value = dylib_path.as_os_str().as_bytes().to_vec();
    if !prior.is_empty() {
        injection_value.push(b':');
        injection_value.extend_from_slice(prior.as_bytes());
    }
    let mut entry = ENV_HOOK_INJECTION.as_bytes().to_vec();
    entry.push(b'=');
    entry.extend_from_slice(&injection_value);
    env.push(
        CString::new(entry)
            .map_err(|e| std::io::Error::other(format!("hook env contains NUL: {e}")))?,
    );

    // STT_GUARD_SNAPSHOT_MANIFEST: absolute path for the dylib to read at ctor time.
    let mut entry2 = ENV_MANIFEST.as_bytes().to_vec();
    entry2.push(b'=');
    entry2.extend_from_slice(manifest_path.as_os_str().as_bytes());
    env.push(
        CString::new(entry2)
            .map_err(|e| std::io::Error::other(format!("MANIFEST env contains NUL: {e}")))?,
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
    let mut argv_ptrs: Vec<*mut libc::c_char> = argv
        .iter()
        .map(|c| c.as_ptr() as *mut libc::c_char)
        .collect();
    argv_ptrs.push(std::ptr::null_mut());

    let mut envp_ptrs: Vec<*mut libc::c_char> = env
        .iter()
        .map(|c| c.as_ptr() as *mut libc::c_char)
        .collect();
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

/// v0.3 — Spawn the wrapped command and return (`Child`, `pgid`).
///
/// Unlike `spawn_wrapped` (which uses raw `posix_spawnp` and returns a bare pid),
/// this variant uses `std::process::Command` so the orchestrator can:
///   1. Install the SIGINT handler with the known pgid BEFORE calling `child.wait()`.
///   2. Call `child.wait()` after the SIGINT handler is in place.
///
/// The child is set as its own process-group leader via `std::os::unix::process::CommandExt::process_group(0)`
/// which internally calls `setpgid(0,0)` in the child before exec — equivalent to
/// POSIX_SPAWN_SETPGROUP. The returned pgid is `child.id() as i32`.
///
/// Environment setup mirrors `spawn_wrapped`: inherits current env, strips
/// managed vars, then adds the platform hook env var and STT_GUARD_SNAPSHOT_MANIFEST.
pub fn spawn_wrapped_with_pgid(
    command: &[OsString],
    manifest_path: &Path,
    state_dir: &Path,
    _run_uuid: &str,
) -> Result<(std::process::Child, i32), crate::CliError> {
    use std::os::unix::process::CommandExt;

    if command.is_empty() {
        return Err(crate::CliError::Other("command is empty".into()));
    }

    let dylib =
        crate::locate::find_dylib().map_err(|e| crate::CliError::DylibNotFound(e.to_string()))?;

    let prior_injection = std::env::var_os(ENV_HOOK_INJECTION).unwrap_or_default();
    let mut injection_value = dylib.as_os_str().to_os_string();
    if !prior_injection.is_empty() {
        let mut v = std::ffi::OsString::from(":");
        v.push(&prior_injection);
        injection_value.push(v);
    }

    let mut cmd = std::process::Command::new(&command[0]);
    cmd.args(&command[1..]);

    for (k, v) in std::env::vars_os() {
        let kb = k.as_bytes();
        if kb == ENV_HOOK_INJECTION.as_bytes()
            || kb == ENV_MANIFEST.as_bytes()
            || kb == ENV_STATE.as_bytes()
            || kb == ENV_DAEMON_SOCKET.as_bytes()
            || kb == ENV_TRUSTED_SIGNERS_MANIFEST.as_bytes()
            || kb == ENV_ALLOW_TEST_SIGNER.as_bytes()
        {
            continue;
        }
        cmd.env(k, v);
    }

    cmd.env(ENV_HOOK_INJECTION, &injection_value);
    cmd.env(ENV_MANIFEST, manifest_path);
    cmd.env(ENV_STATE, state_dir);

    // Make the child its own pgid leader (POSIX_SPAWN_SETPGROUP equivalent).
    // process_group(0) calls setpgid(0,0) in the child, making it its own leader.
    cmd.process_group(0);

    let child = cmd.spawn().map_err(crate::CliError::Io)?;
    let pgid = child.id() as i32;
    Ok((child, pgid))
}
