//! Verifies that `spawn_wrapped` does NOT propagate STT_GUARD_DAEMON_SOCKET
//! into the child's environment (the hook derives the socket path from
//! well_known_state_dir() instead).

use std::ffi::OsStr;
use std::io::Read;
use std::path::PathBuf;
use std::sync::Mutex;

const CAPTURE_OUT_ENV: &str = "GUARD_TEST_SOCKET_CAPTURE_OUT";
const STALE_SOCKET_ENV: &str = "STT_GUARD_DAEMON_SOCKET";
static ENV_LOCK: Mutex<()> = Mutex::new(());

struct ScopedEnv {
    keys: Vec<&'static str>,
}

impl ScopedEnv {
    fn set(vars: &[(&'static str, &OsStr)]) -> Self {
        for (key, value) in vars {
            unsafe {
                std::env::set_var(key, value);
            }
        }
        Self {
            keys: vars.iter().map(|(key, _)| *key).collect(),
        }
    }
}

impl Drop for ScopedEnv {
    fn drop(&mut self) {
        for key in &self.keys {
            unsafe {
                std::env::remove_var(key);
            }
        }
    }
}

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
    let _env_lock = ENV_LOCK.lock().unwrap();
    let dylib = built_hook_dylib();
    let mfst = tempfile::NamedTempFile::new().unwrap();
    let outdir = tempfile::tempdir().unwrap();
    let outfile = outdir.path().join("sock_capture");

    let stale_socket = OsStr::new("/tmp/stale-stt-guard.sock");
    let _env = ScopedEnv::set(&[
        (CAPTURE_OUT_ENV, outfile.as_os_str()),
        (STALE_SOCKET_ENV, stale_socket),
    ]);

    let prog = std::env::current_exe().expect("current test binary path");
    let args: Vec<&OsStr> = vec![
        OsStr::new("--ignored"),
        OsStr::new("--exact"),
        OsStr::new("capture_socket_child_helper"),
    ];

    let pid =
        guard_cli::spawn::spawn_wrapped(&prog, &args, &dylib, mfst.path()).expect("spawn_wrapped");
    assert!(pid > 0);

    let mut status: libc::c_int = 0;
    unsafe { libc::waitpid(pid, &mut status, 0) };
    assert!(
        libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0,
        "helper test process must exit successfully, status={status}"
    );

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

#[test]
#[ignore = "spawn helper invoked by spawn_wrapped_does_not_set_daemon_socket_env_var"]
fn capture_socket_child_helper() {
    let Some(outfile) = std::env::var_os(CAPTURE_OUT_ENV) else {
        return;
    };
    let socket = std::env::var_os(STALE_SOCKET_ENV).unwrap_or_default();
    std::fs::write(outfile, socket.as_encoded_bytes()).expect("write captured socket env");
}
