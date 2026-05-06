//! Verifies that `spawn_wrapped` puts `SENTINEL_DAEMON_SOCKET=<socket_path>`
//! in the wrapped child's environment (plan 02-06b).
//!
//! The dylib's `cache_daemon_socket_from_env` reads the env var at ctor time
//! to talk to the daemon for fork/exec/dylib_loaded events; without this,
//! Phase 2's whole IPC pipeline is no-op.

use std::ffi::OsStr;
use std::io::Read;
use std::path::Path;

#[test]
fn spawn_wrapped_propagates_daemon_socket_env_var() {
    // Use /bin/sh -c 'printenv SENTINEL_DAEMON_SOCKET' so the child prints the
    // env var to stdout. We capture it via a temp file because the existing
    // spawn API doesn't expose stdout — `posix_spawnp` inherits the parent's
    // file descriptors, so the child's stdout goes to our test's stdout.
    //
    // Instead of trying to capture from the child's stdout directly, we have
    // the shell write the value to a tempfile and assert on its contents.
    let dylib = tempfile::NamedTempFile::new().unwrap();
    let mfst = tempfile::NamedTempFile::new().unwrap();
    let outdir = tempfile::tempdir().unwrap();
    let outfile = outdir.path().join("sock_capture");

    // Distinctive socket path — does not need to exist; we just want it in envp.
    let fake_sock = std::path::PathBuf::from("/tmp/sentinel-test-socket-marker.sock");

    let prog = Path::new("/bin/sh");
    let cmd = format!("printenv SENTINEL_DAEMON_SOCKET > {}", outfile.display());
    let args: Vec<&OsStr> = vec![OsStr::new("-c"), OsStr::new(&cmd)];

    let pid = sentinel_cli::spawn::spawn_wrapped(
        prog,
        &args,
        dylib.path(),
        mfst.path(),
        &fake_sock,
    )
    .expect("spawn_wrapped");
    assert!(pid > 0);

    // Reap.
    let mut status: libc::c_int = 0;
    unsafe { libc::waitpid(pid, &mut status, 0) };

    // Read the captured value.
    let mut s = String::new();
    std::fs::File::open(&outfile)
        .expect("output file must exist (child ran)")
        .read_to_string(&mut s)
        .expect("read output");
    let captured = s.trim();
    assert_eq!(
        captured,
        fake_sock.display().to_string(),
        "SENTINEL_DAEMON_SOCKET must equal the path passed to spawn_wrapped",
    );
}
