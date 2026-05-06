//! E2E harness: invokes posix_spawn with env_clear() to trigger
//! TREE-06 EnvNotPropagatedGap. The wrapped sentinel run inherits
//! all three SENTINEL_* / DYLD_* env vars; this harness intentionally
//! drops them when spawning the inner child.

use std::ffi::CString;
use std::ptr;

fn main() {
    // Spawn /bin/sh -c 'true' with an EMPTY envp array (just a NULL terminator).
    // The child will exec 'true' which exits 0; the dylib's pre-spawn inspector
    // (envp.rs::should_emit_env_not_propagated_gap) observes the empty envp
    // and emits the gap IPC pre-spawn.
    let path = CString::new("/bin/sh").expect("cstring /bin/sh");
    let arg0 = CString::new("/bin/sh").expect("cstring arg0");
    let arg1 = CString::new("-c").expect("cstring -c");
    let arg2 = CString::new("true").expect("cstring true");

    // Use mut pointers per posix_spawn signature.
    let argv_mut: [*mut libc::c_char; 4] = [
        arg0.as_ptr() as *mut libc::c_char,
        arg1.as_ptr() as *mut libc::c_char,
        arg2.as_ptr() as *mut libc::c_char,
        ptr::null_mut(),
    ];

    // Empty envp — JUST the NULL terminator. This is the "env_clear()" case
    // that TREE-06 detects.
    let envp_mut: [*mut libc::c_char; 1] = [ptr::null_mut()];

    let mut pid: libc::pid_t = 0;
    let rc = unsafe {
        libc::posix_spawn(
            &mut pid as *mut libc::pid_t,
            path.as_ptr(),
            ptr::null(),
            ptr::null(),
            argv_mut.as_ptr(),
            envp_mut.as_ptr(),
        )
    };
    if rc != 0 {
        eprintln!("posix_spawn failed: errno={rc}");
        std::process::exit(1);
    }
    // Reap the child.
    let mut status: libc::c_int = 0;
    unsafe {
        libc::waitpid(pid, &mut status, 0);
    }
    // Print the child exit code so the e2e test can correlate.
    #[allow(unused_unsafe)]
    let exit_code = unsafe { libc::WEXITSTATUS(status) };
    println!("env_clear_posix_spawn: child pid={pid} exit={exit_code}");
    // The harness itself always exits 0; the e2e test asserts on:
    //   (a) this exit being 0, and
    //   (b) the daemon stderr containing both `TREE-06` AND `env-not-propagated`.
}
