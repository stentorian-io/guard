//! Verifies that `spawn_wrapped` does NOT propagate SENTINEL_DAEMON_SOCKET
//! into the child's environment (the hook derives the socket path from
//! well_known_state_dir() instead).

use std::ffi::OsStr;
use std::io::Read;
use std::path::Path;

#[test]
fn spawn_wrapped_does_not_set_daemon_socket_env_var() {
    let dylib = tempfile::NamedTempFile::new().unwrap();
    let mfst = tempfile::NamedTempFile::new().unwrap();
    let outdir = tempfile::tempdir().unwrap();
    let outfile = outdir.path().join("sock_capture");

    let prog = Path::new("/bin/sh");
    let cmd = format!(
        "printenv SENTINEL_DAEMON_SOCKET > {} 2>/dev/null; true",
        outfile.display()
    );
    let args: Vec<&OsStr> = vec![OsStr::new("-c"), OsStr::new(&cmd)];

    let pid = sentinel_cli::spawn::spawn_wrapped(
        prog,
        &args,
        dylib.path(),
        mfst.path(),
    )
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
        "SENTINEL_DAEMON_SOCKET must not be in the child environment, got: {s:?}"
    );
}
