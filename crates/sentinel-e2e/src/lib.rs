//! E2E test harness for Phase 1 success criteria.
//!
//! Provides:
//!   - DaemonHarness: spawns sentineld serve in a tempdir; waits for ready;
//!     stops on Drop.
//!   - resolve_node(): finds a usable non-hardened node binary; returns Err
//!     with a clear skip message if none available.
//!   - resolve_dylib(): the cargo target/debug/libsentinel_hook.dylib path
//!     (assumes `cargo build` has produced it; cargo's test runner does).

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

pub struct DaemonHarness {
    pub state_dir: PathBuf,
    pub socket: PathBuf,
    pub manifest: PathBuf,
    /// The TempDir that owns the home directory (and must be kept alive for
    /// the lifetime of the harness).
    pub home: tempfile::TempDir,
    pub child: Child,
    /// A second TempDir under /tmp for the state_dir/socket — kept short to
    /// stay under macOS's 104-byte Unix socket path limit (ISS-12).
    _state_tmp: tempfile::TempDir,
}

impl DaemonHarness {
    /// Start sentineld serve in a fresh tempdir as $HOME, wait for daemon.ready.
    ///
    /// ISS-07 remediation — STATE_DIR ALIGNMENT CONTRACT:
    /// The daemon receives `--state-dir <state_dir>` explicitly (authoritative).
    /// Tests that subsequently invoke the CLI MUST pass BOTH:
    ///   - `HOME=<harness.home.path()>` so the CLI's `default_state_dir()`
    ///     fallback (HOME-derivation) lands in the same dir, AND
    ///   - `SENTINEL_STATE_DIR=<state_dir>` (defense in depth — explicit override
    ///     ensures the CLI uses the harness state dir even if `default_state_dir()`
    ///     changes its derivation rule).
    /// This dual env-var pattern is the ISS-07 fix: the daemon and CLI use the
    /// same state_dir without relying on HOME-derivation alone.
    ///
    /// ISS-12: macOS Unix domain socket paths must be < 104 bytes. The default
    /// `tempfile::tempdir()` creates paths under /var/folders/…/T/ which can
    /// exceed the limit when suffixed with the state-dir + socket file name.
    /// The fix: create a SHORT tempdir under /tmp for the state_dir/socket
    /// (e.g. /tmp/se2e_XXXXXXXX/sentineld.sock — around 36 bytes) and a
    /// SEPARATE home dir (which does not need to hold the socket).
    pub fn start() -> std::io::Result<Self> {
        let home = tempfile::tempdir()?;

        // Short state dir under /tmp so the socket path stays under 104 bytes.
        // e.g. /tmp/.se2eXXXXXX/sentineld.sock => ~32 bytes (well under limit).
        let state_tmp = tempfile::Builder::new()
            .prefix(".se2e")
            .tempdir_in("/tmp")?;
        let state_dir = state_tmp.path().to_path_buf();

        let logs = home.path().join("Library/Logs/Sentinel");
        std::fs::create_dir_all(&logs)?;

        let daemon_bin = cargo_target_dir().join("sentineld");
        if !daemon_bin.exists() {
            return Err(std::io::Error::other(format!(
                "sentineld binary not found at {} — run cargo build first",
                daemon_bin.display()
            )));
        }

        let child = Command::new(&daemon_bin)
            .arg("serve")
            .arg("--state-dir")
            .arg(&state_dir)
            .env_clear() // clean slate; no leaked DYLD_*
            .env("HOME", home.path())
            .env("PATH", std::env::var_os("PATH").unwrap_or_default())
            .env("RUST_LOG", "info")
            // Phase 4 plan 04-03: e2e tests must NOT trigger real OSV/GHSA
            // git fetches against github.com (offline CI flakes; per-run
            // network cost). Hermetic Phase 4 e2e tests (plan 04-04) opt out
            // of this skip and point at file:// fixtures via
            // SENTINEL_FEED_URL_OVERRIDE_*.
            .env("SENTINEL_SKIP_FEED_FETCH", "1")
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;

        let ready = sentinel_daemon::state_dir::ready_path(&state_dir);
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            if ready.exists() {
                break;
            }
            if Instant::now() > deadline {
                return Err(std::io::Error::other(format!(
                    "daemon.ready not appeared at {} within 5s",
                    ready.display()
                )));
            }
            std::thread::sleep(Duration::from_millis(50));
        }

        Ok(Self {
            socket: sentinel_daemon::state_dir::socket_path(&state_dir),
            manifest: sentinel_daemon::state_dir::manifest_path(&state_dir),
            state_dir,
            home,
            child,
            _state_tmp: state_tmp,
        })
    }

    /// Drains the daemon child's currently-buffered stderr into a String without
    /// blocking and without consuming `self`. Sets the underlying pipe to
    /// non-blocking via `fcntl(O_NONBLOCK)` for the duration of the read so
    /// the call returns whatever is available right now.
    ///
    /// Used by e2e tests that need to make HARD assertions on the daemon's log
    /// output (e.g. TREE-06 gap markers in env_not_propagated.rs).
    ///
    /// Repeated calls return cumulative stderr produced since the process was
    /// started (the OS pipe buffer grows until drained; this drains everything
    /// currently available).
    pub fn drain_stderr(&mut self) -> String {
        use std::io::Read;
        use std::os::fd::AsRawFd;

        let stderr = match self.child.stderr.as_mut() {
            Some(s) => s,
            None => return String::new(),
        };
        let fd = stderr.as_raw_fd();
        // Set O_NONBLOCK so we don't hang waiting for EOF.
        unsafe {
            let flags = libc::fcntl(fd, libc::F_GETFL, 0);
            if flags >= 0 {
                libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK);
            }
        }
        let mut buf = Vec::with_capacity(4096);
        let mut chunk = [0u8; 1024];
        loop {
            match stderr.read(&mut chunk) {
                Ok(0) => break,                                                    // EOF
                Ok(n) => buf.extend_from_slice(&chunk[..n]),
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,    // no more data
                Err(_) => break,
            }
            if buf.len() > (1 << 20) {
                break; // 1 MiB cap, defensive
            }
        }
        String::from_utf8_lossy(&buf).into_owned()
    }
}

impl Drop for DaemonHarness {
    fn drop(&mut self) {
        // Send SIGTERM, wait briefly, SIGKILL if still alive.
        let pid = self.child.id() as libc::pid_t;
        unsafe {
            libc::kill(pid, libc::SIGTERM);
        }
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            match self.child.try_wait() {
                Ok(Some(_)) => return,
                Ok(None) => {
                    if Instant::now() > deadline {
                        unsafe {
                            libc::kill(pid, libc::SIGKILL);
                        }
                        let _ = self.child.wait();
                        return;
                    }
                    std::thread::sleep(Duration::from_millis(50));
                }
                Err(_) => return,
            }
        }
    }
}

/// ISS-11 remediation: anchor at workspace root via `Cargo.lock`, then derive
/// `target/<profile>` from there.
///
/// Strategy:
///   1. Walk up from CARGO_MANIFEST_DIR looking for `Cargo.lock` (anchors the
///      workspace root deterministically — `Cargo.lock` lives ONLY at the
///      workspace root).
///   2. Honor `CARGO_TARGET_DIR` env var if set (cargo respects it for build
///      artifacts; tests must respect the same convention).
///   3. Otherwise default to `<workspace_root>/target`.
///   4. Pick the profile from the test binary path: if `current_exe()` lives
///      under `.../release/`, use `release`; otherwise `debug`.
pub fn cargo_workspace_root() -> PathBuf {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let mut cur: &Path = &manifest_dir;
    loop {
        if cur.join("Cargo.lock").exists() {
            return cur.to_path_buf();
        }
        match cur.parent() {
            Some(p) => cur = p,
            None => panic!(
                "could not locate Cargo.lock walking up from {} — workspace root \
                 anchor missing (ISS-11)",
                manifest_dir.display()
            ),
        }
    }
}

pub fn cargo_target_dir() -> PathBuf {
    // Prefer CARGO_TARGET_DIR (cargo's documented override) if set.
    let target_root = match std::env::var_os("CARGO_TARGET_DIR") {
        Some(p) => PathBuf::from(p),
        None => cargo_workspace_root().join("target"),
    };
    // Detect profile from current_exe location (path contains "/release/" or
    // "/debug/"); default to debug if neither matches (defensive).
    let exe = std::env::current_exe().expect("current_exe");
    let exe_str = exe.to_string_lossy();
    let profile = if exe_str.contains("/release/") {
        "release"
    } else if exe_str.contains("/debug/") {
        "debug"
    } else {
        "debug"
    };
    let dir = target_root.join(profile);
    if !dir.exists() {
        panic!(
            "cargo target dir {} does not exist — run `cargo build --workspace` \
             (or `cargo build --workspace --release` for release tests) before \
             running e2e tests (ISS-11)",
            dir.display()
        );
    }
    dir
}

/// Find a usable non-hardened node binary. Returns Err(skip_message) if none
/// can be found. On macOS, nvm node v18.17.0 has `hardened_indicators=1` per
/// spike A2, but Homebrew node (ad-hoc signed) does not. This function
/// prefers Homebrew node to avoid that pitfall.
pub fn resolve_node() -> Result<PathBuf, String> {
    if let Some(p) = std::env::var_os("SENTINEL_E2E_NODE") {
        let p = PathBuf::from(p);
        if !p.exists() {
            return Err(format!(
                "SENTINEL_E2E_NODE={} does not exist",
                p.display()
            ));
        }
        return Ok(p);
    }
    // Prefer Homebrew node (non-hardened, ad-hoc signed) over nvm node.
    // Homebrew node is at /opt/homebrew/bin/node on Apple Silicon.
    let homebrew_node = PathBuf::from("/opt/homebrew/bin/node");
    if homebrew_node.is_file() {
        return Ok(homebrew_node);
    }
    // Fall back to `which node` via $PATH lookup.
    for dir in std::env::var_os("PATH")
        .unwrap_or_default()
        .to_string_lossy()
        .split(':')
        .map(|s| s.to_string())
        .collect::<Vec<_>>()
    {
        let cand = Path::new(&dir).join("node");
        if cand.is_file() {
            return Ok(cand);
        }
    }
    Err("node not found on PATH; set SENTINEL_E2E_NODE or install Homebrew node".into())
}

/// Path to the test-built libsentinel_hook.dylib.
pub fn resolve_dylib() -> PathBuf {
    cargo_target_dir().join("libsentinel_hook.dylib")
}

/// Path to the sentinel CLI binary.
pub fn resolve_cli() -> PathBuf {
    cargo_target_dir().join("sentinel")
}
