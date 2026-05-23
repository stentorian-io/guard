//! Verifies that `spawn_wrapped` does NOT propagate STT_GUARD_DAEMON_SOCKET
//! into the child's environment (the hook derives the socket path from
//! well_known_state_dir() instead).

use std::ffi::OsStr;
use std::io::Read;
use std::path::{Path, PathBuf};

fn built_hook_dylib() -> PathBuf {
    let mut dir = std::env::current_exe().expect("current test binary path");
    while dir.pop() {
        let candidate = dir.join("libguard_hook.dylib");
        if candidate.exists() {
            return candidate;
        }
    }
    panic!("libguard_hook.dylib must be built before spawn tests run");
}

#[test]
fn spawn_wrapped_does_not_set_daemon_socket_env_var() {
    let dylib = built_hook_dylib();
    let mfst = tempfile::NamedTempFile::new().unwrap();
    let outdir = tempfile::tempdir().unwrap();
    let outfile = outdir.path().join("sock_capture");

    let prog = Path::new("/bin/sh");
    let cmd = format!(
        "printenv STT_GUARD_DAEMON_SOCKET > {} 2>/dev/null; true",
        outfile.display()
    );
    let args: Vec<&OsStr> = vec![OsStr::new("-c"), OsStr::new(&cmd)];

    let pid = guard_cli::spawn::spawn_wrapped(prog, &args, &dylib, mfst.path())
        .expect("spawn_wrapped");
    assert!(pid > 0);

    let mut status: libc::c_int = 0;
    unsafe { libc::waitpid(pid, &mut status, 0) };

    let mut s = String::new();
    std::fs::File::open(&outfile)
        .expect("output file must exist")
        .read_to_string(&mut s)
        .expect("read output");
    assert!(
        s.trim().is_empty(),
        "STT_GUARD_DAEMON_SOCKET must not be in the child environment, got: {s:?}"
    );
}
