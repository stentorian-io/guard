//! E2E test harness for v0.1 success criteria.
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
use std::sync::mpsc;
use std::time::{Duration, Instant};

pub mod test_support;

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
        Self::start_with_env(&[])
    }

    /// Env-aware variant. Pairs in `extra` later in the slice override
    /// earlier ones; `extra` overrides the harness baseline
    /// (HOME / PATH / RUST_LOG=info).
    pub fn start_with_env(extra: &[(&str, &str)]) -> std::io::Result<Self> {
        Self::start_with_env_and_home_setup(extra, |_| Ok(()))
    }

    /// Like `start_with_env`, but calls `setup(home_path)` after creating the
    /// temp HOME but before spawning the daemon. Useful for creating directories
    /// that the daemon needs to see at startup (e.g. ~/Library/LaunchAgents for
    /// the persistence watcher).
    pub fn start_with_env_and_home_setup(
        extra: &[(&str, &str)],
        setup: impl FnOnce(&Path) -> std::io::Result<()>,
    ) -> std::io::Result<Self> {
        let home = tempfile::tempdir()?;

        setup(home.path())?;

        // Short state dir under /tmp so the socket path stays under 104 bytes.
        // e.g. /tmp/.se2eXXXXXX/sentineld.sock => ~32 bytes (well under limit).
        let state_tmp = tempfile::Builder::new()
            .prefix(".se2e")
            .tempdir_in("/tmp")?;
        let state_dir = state_tmp.path().to_path_buf();

        let (socket, manifest, child) = spawn_daemon_into(&state_dir, home.path(), extra)?;

        Ok(Self {
            socket,
            manifest,
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
                Ok(0) => break, // EOF
                Ok(n) => buf.extend_from_slice(&chunk[..n]),
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break, // no more data
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
    // Prefer Homebrew node (non-hardened, ad-hoc signed) over nvm node.
    let homebrew_node = PathBuf::from("/opt/homebrew/bin/node");
    if homebrew_node.is_file() {
        return Ok(homebrew_node);
    }
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
    Err("node not found on PATH; install Homebrew node or add node to PATH".into())
}

/// Path to the test-built libsentinel_hook.dylib.
///
/// Panics with an actionable message if the dylib hasn't been built yet.
/// E2E tests require `cargo build --workspace` before `cargo test -p sentinel-e2e`.
pub fn resolve_dylib() -> PathBuf {
    let p = cargo_target_dir().join("libsentinel_hook.dylib");
    if !p.exists() {
        panic!(
            "libsentinel_hook.dylib not found at {} — \
             run `cargo build --workspace` before running E2E tests",
            p.display()
        );
    }
    p
}

/// Path to the sentinel CLI binary.
///
/// Panics with an actionable message if the CLI hasn't been built yet.
pub fn resolve_cli() -> PathBuf {
    let p = cargo_target_dir().join("sentinel");
    if !p.exists() {
        panic!(
            "sentinel binary not found at {} — \
             run `cargo build --workspace` before running E2E tests",
            p.display()
        );
    }
    p
}

/// Read PTY output until `needle` appears, EOF is reached, or `timeout`
/// expires. PTY output may use carriage returns without newlines, so callers
/// must not block on `BufRead::read_line` when enforcing prompt deadlines.
pub fn read_pty_until(
    mut reader: Box<dyn std::io::Read + Send>,
    needle: &str,
    timeout: Duration,
) -> Result<String, String> {
    let (tx, rx) = mpsc::channel();
    std::thread::Builder::new()
        .name("sentinel-e2e-pty-reader".into())
        .spawn(move || {
            let mut chunk = [0u8; 512];
            loop {
                match reader.read(&mut chunk) {
                    Ok(0) => {
                        let _ = tx.send(None);
                        break;
                    }
                    Ok(n) => {
                        let text = String::from_utf8_lossy(&chunk[..n]).into_owned();
                        if tx.send(Some(text)).is_err() {
                            break;
                        }
                    }
                    Err(e) => {
                        let _ = tx.send(Some(format!("\n[PTY read error: {e}]\n")));
                        let _ = tx.send(None);
                        break;
                    }
                }
            }
        })
        .map_err(|e| format!("spawn PTY reader: {e}"))?;

    let deadline = Instant::now() + timeout;
    let mut buf = String::new();
    loop {
        if buf.contains(needle) {
            return Ok(buf);
        }
        let now = Instant::now();
        if now >= deadline {
            return Err(format!(
                "PTY output did not contain {needle:?} within {:?}; buffer:\n{buf}",
                timeout,
            ));
        }
        let remaining = deadline.saturating_duration_since(now);
        let wait = remaining.min(Duration::from_millis(100));
        match rx.recv_timeout(wait) {
            Ok(Some(text)) => buf.push_str(&text),
            Ok(None) => {
                return Err(format!("PTY reached EOF before {needle:?}; buffer:\n{buf}",));
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                return Err(format!(
                    "PTY reader disconnected before {needle:?}; buffer:\n{buf}",
                ));
            }
        }
    }
}

/// Path to the persistence_write_probe helper binary.
///
/// Panics with an actionable message if the probe hasn't been built yet.
pub fn resolve_probe() -> PathBuf {
    let p = cargo_target_dir().join("persistence_write_probe");
    if !p.exists() {
        panic!(
            "persistence_write_probe not found at {} — \
             run `cargo build --workspace` before running E2E tests",
            p.display()
        );
    }
    p
}

/// Shared spawn helper used by both `DaemonHarness::start_with_env` (initial
/// start, owns fresh tempdirs) and `StoppedHarness::restart_with_env`
/// (re-spawn against preserved tempdirs).
///
/// Ensures both code paths use identical spawn semantics — the env baseline
/// (env_clear + HOME + PATH + RUST_LOG=info), the SIGTERM-on-Drop chain
/// (handled by DaemonHarness::Drop), and the daemon.ready 5s wait. Tempdir
/// CREATION is the caller's responsibility; this helper takes pre-existing
/// state_dir + home_path borrows and returns the (socket, manifest, child)
/// triple the caller assembles into a DaemonHarness.
fn spawn_daemon_into(
    state_dir: &Path,
    home_path: &Path,
    extra: &[(&str, &str)],
) -> std::io::Result<(PathBuf, PathBuf, Child)> {
    let logs = home_path.join("Library/Logs/Sentinel");
    std::fs::create_dir_all(&logs)?;

    let daemon_bin = cargo_target_dir().join("sentineld");
    if !daemon_bin.exists() {
        return Err(std::io::Error::other(format!(
            "sentineld binary not found at {} — run cargo build first",
            daemon_bin.display()
        )));
    }

    // Restart paths reuse state_dir. Clear stale readiness before spawning so
    // the wait below observes the new daemon, not a previous daemon.ready file.
    let ready = sentinel_daemon::state_dir::ready_path(state_dir);
    match std::fs::remove_file(&ready) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e),
    }

    let mut cmd = Command::new(&daemon_bin);
    cmd.arg("serve")
        .arg("--state-dir")
        .arg(state_dir)
        .env_clear() // clean slate; no leaked DYLD_*
        .env("HOME", home_path)
        .env("PATH", std::env::var_os("PATH").unwrap_or_default())
        .env("RUST_LOG", "info");
    for (k, v) in extra {
        cmd.env(*k, *v);
    }
    let child = cmd.stdout(Stdio::piped()).stderr(Stdio::piped()).spawn()?;

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

    let socket = sentinel_daemon::state_dir::socket_path(state_dir);
    let manifest = sentinel_daemon::state_dir::manifest_path(state_dir);
    Ok((socket, manifest, child))
}

/// A daemon that has been gracefully stopped while preserving its state_dir
/// and home tempdirs for restart. See `DaemonHarness::stop_preserving_state`.
pub struct StoppedHarness {
    pub state_dir: PathBuf,
    pub home: tempfile::TempDir,
    _state_tmp: tempfile::TempDir, // owns state_dir lifetime across restart
}

impl DaemonHarness {
    /// Stop the daemon (SIGTERM, wait up to 2s, SIGKILL fallback) WITHOUT
    /// dropping the state_dir or home tempdirs. Returns a StoppedHarness that
    /// holds the dirs alive; call `restart_with_env(...)` to spawn a fresh
    /// daemon over the same state.
    pub fn stop_preserving_state(mut self) -> std::io::Result<StoppedHarness> {
        // Mirror the SIGTERM->wait->SIGKILL chain from Drop.
        let pid = self.child.id() as libc::pid_t;
        unsafe {
            libc::kill(pid, libc::SIGTERM);
        }
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            match self.child.try_wait() {
                Ok(Some(_)) => break,
                Ok(None) => {
                    if Instant::now() > deadline {
                        unsafe {
                            libc::kill(pid, libc::SIGKILL);
                        }
                        let _ = self.child.wait();
                        break;
                    }
                    std::thread::sleep(Duration::from_millis(50));
                }
                Err(_) => break,
            }
        }
        // We need to move state_dir + home + _state_tmp out of `self` while
        // preventing `DaemonHarness::Drop` from running (its child has been
        // waited above; running Drop would attempt a second wait, which is
        // harmless but redundant — and direct field-by-field move is forbidden
        // for types implementing Drop). Use ManuallyDrop + ptr::read.
        //
        // CR-04: previously this block also performed
        //   let _ = std::ptr::read(&me.child);
        //   let _ = std::ptr::read(&me.socket);
        //   let _ = std::ptr::read(&me.manifest);
        // to "explicitly drop" the unread fields. That was UB: ptr::read makes
        // a bitwise copy and the new copy gets dropped at end-of-statement, so
        // for `Child` (which owns stdin/stdout/stderr pipe `File`s) this dropped
        // a duplicate of those `File`s, racing FD reuse with the original.
        // ManuallyDrop already suppresses Drop on `me` itself, so any unread
        // fields are simply leaked when `me` goes out of scope — that is the
        // intended behavior for `child` (already waited), `socket` (PathBuf —
        // a small allocation leak, no resource impact), and `manifest` (same).
        //
        // SAFETY: `self.child` has already been waited (or killed and waited)
        // above. After the three reads below, we never touch `me` again.
        // ManuallyDrop suppresses the type's destructor, so the unread fields
        // (`child`, `socket`, `manifest`) are leaked when `me` itself goes out
        // of scope. The leaks are bounded (one Child whose process is already
        // reaped + two PathBufs) and self-recoverable on harness reuse.
        let me = std::mem::ManuallyDrop::new(self);
        unsafe {
            let state_dir = std::ptr::read(&me.state_dir);
            let home = std::ptr::read(&me.home);
            let _state_tmp = std::ptr::read(&me._state_tmp);
            Ok(StoppedHarness {
                state_dir,
                home,
                _state_tmp,
            })
        }
    }
}

impl StoppedHarness {
    /// Spawn a fresh daemon over the preserved state_dir + home. Mirrors
    /// DaemonHarness::start_with_env spawn semantics (uses the same
    /// `spawn_daemon_into` helper) but skips tempdir creation.
    pub fn restart_with_env(self, extra_env: &[(&str, &str)]) -> std::io::Result<DaemonHarness> {
        let StoppedHarness {
            state_dir,
            home,
            _state_tmp,
        } = self;
        let (socket, manifest, child) = spawn_daemon_into(&state_dir, home.path(), extra_env)?;
        Ok(DaemonHarness {
            state_dir,
            socket,
            manifest,
            home,
            child,
            _state_tmp,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg_attr(not(target_os = "macos"), ignore)]
    #[test]
    fn stop_preserving_state_roundtrip() {
        let h = DaemonHarness::start().expect("start");
        let preserved_state = h.state_dir.clone();
        let preserved_home = h.home.path().to_path_buf();
        let stopped = h.stop_preserving_state().expect("stop");
        assert_eq!(stopped.state_dir, preserved_state);
        assert_eq!(stopped.home.path(), preserved_home);
        let h2 = stopped.restart_with_env(&[]).expect("restart");
        assert_eq!(h2.state_dir, preserved_state);
        assert_eq!(h2.home.path(), preserved_home);
        // Drop h2 normally — confirms the post-restart Drop chain works.
    }
}
