//! E2E harness for v0.1 milestone audit BLOCKER #1 (LOG-02 + VAL-01).
//!
//! Calls `libc::posix_spawn` directly with an explicit envp containing both:
//!   - benign PM env vars (`npm_package_name`, `npm_lifecycle_event`,
//!     `CARGO_PKG_NAME`) that MUST be captured into ProcessNode.pm_env_snapshot
//!   - decoy denylisted secret env vars (`NPM_TOKEN`, `CARGO_REGISTRY_TOKEN`,
//!     `npm_config_authToken`) that MUST be filtered out by the dylib's
//!     defense-in-depth `pm_env_filter` BEFORE the IPC frame is sent.
//!
//! Inherits SENTINEL_DAEMON_SOCKET / SENTINEL_SNAPSHOT_MANIFEST /
//! DYLD_INSERT_LIBRARIES from the wrapped `sentinel run` invocation so the
//! child still loads the dylib and can talk to the daemon. Plus the
//! `SENTINEL_E2E_PROBE` env vars are prepended explicitly into the spawned
//! envp so the test-side filter has known input.
//!
//! Always exits 0 on success regardless of the inner child outcome (the e2e
//! test asserts on daemon stderr, not this harness's exit code).

use std::ffi::CString;
use std::ptr;

const REQUIRED_INHERIT_KEYS: &[&str] = &[
    "DYLD_INSERT_LIBRARIES",
    "SENTINEL_SNAPSHOT_MANIFEST",
    "SENTINEL_DAEMON_SOCKET",
    "PATH",
];

/// PM-relevant env vars our test-side harness ALWAYS injects so the daemon's
/// `pm_env_captured` tracing line carries a known captured count.
const BENIGN_PM_ENV: &[(&str, &str)] = &[
    ("npm_package_name", "test-package"),
    ("npm_package_version", "0.0.1"),
    ("npm_lifecycle_event", "preinstall"),
    ("CARGO_PKG_NAME", "sentinel-e2e-pkg"),
];

/// Decoy denylisted secret env vars. The dylib MUST filter these out before
/// they cross the IPC wire. The daemon's defense-in-depth filter is the
/// authoritative gate, but we want HARD evidence the dylib half is doing its
/// job (otherwise we'd just be testing the daemon's filter, not the BLOCKER #1
/// closure).
const DECOY_SECRETS: &[(&str, &str)] = &[
    ("NPM_TOKEN", "DECOY_should_not_leak_npm_token"),
    ("CARGO_REGISTRY_TOKEN", "DECOY_should_not_leak_cargo_token"),
    ("npm_config_authToken", "DECOY_should_not_leak_npm_authToken"),
];

fn main() {
    // 1. Build envp: inherit the four required keys + add benign PM env + decoys.
    let mut env_pairs: Vec<(String, String)> = Vec::new();
    for k in REQUIRED_INHERIT_KEYS {
        if let Ok(v) = std::env::var(k) {
            env_pairs.push((k.to_string(), v));
        }
    }
    for (k, v) in BENIGN_PM_ENV {
        env_pairs.push((k.to_string(), v.to_string()));
    }
    for (k, v) in DECOY_SECRETS {
        env_pairs.push((k.to_string(), v.to_string()));
    }

    let env_cstrings: Vec<CString> = env_pairs
        .iter()
        .map(|(k, v)| CString::new(format!("{k}={v}")).expect("envp cstring"))
        .collect();
    let mut envp_ptrs: Vec<*mut libc::c_char> = env_cstrings
        .iter()
        .map(|c| c.as_ptr() as *mut libc::c_char)
        .collect();
    envp_ptrs.push(ptr::null_mut());

    // 2. Build argv: /bin/sh -c 'true'. The inner /bin/sh is hardened (Apple
    //    SIP-protected), so the dylib WILL NOT load into it — but that does
    //    not matter: the dylib is loaded into THIS process (the wrapped
    //    sentinel run child), and our posix_spawn call IS what we're
    //    intercepting. The dylib captures envp at the call site, not from
    //    the child.
    let path = CString::new("/bin/sh").expect("cstring /bin/sh");
    let arg0 = CString::new("/bin/sh").expect("cstring arg0");
    let arg1 = CString::new("-c").expect("cstring -c");
    let arg2 = CString::new("true").expect("cstring true");
    let argv: [*mut libc::c_char; 4] = [
        arg0.as_ptr() as *mut libc::c_char,
        arg1.as_ptr() as *mut libc::c_char,
        arg2.as_ptr() as *mut libc::c_char,
        ptr::null_mut(),
    ];

    let mut pid: libc::pid_t = 0;
    let rc = unsafe {
        libc::posix_spawn(
            &mut pid as *mut libc::pid_t,
            path.as_ptr(),
            ptr::null(),
            ptr::null(),
            argv.as_ptr(),
            envp_ptrs.as_ptr(),
        )
    };
    if rc != 0 {
        eprintln!("pm_env_posix_spawn: posix_spawn failed errno={rc}");
        std::process::exit(1);
    }

    // Reap the child so the daemon's tree GC sees a clean exit.
    let mut status: libc::c_int = 0;
    unsafe {
        libc::waitpid(pid, &mut status, 0);
    }
    let exit_code = libc::WEXITSTATUS(status);
    println!("pm_env_posix_spawn: child pid={pid} exit={exit_code}");
}
