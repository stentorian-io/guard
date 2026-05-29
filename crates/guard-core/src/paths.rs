//! Centralised filesystem layout and well-known constants.
//!
//! Every crate that needs a path, filename, or env-var name imports from here
//! rather than declaring its own copy. The `state_dir` functions are the only
//! place that reads `STT_GUARD_STATE_DIR` or derives the platform default.

use std::path::{Path, PathBuf};

// ---------------------------------------------------------------------------
// Well-known directory names
// ---------------------------------------------------------------------------

pub const APP_NAME: &str = "Stentorian Guard";

/// System-wide state directory (hardened install, root-owned).
#[cfg(target_os = "macos")]
pub const SYSTEM_STATE_DIR: &str = "/Library/Application Support/Stentorian Guard";
#[cfg(target_os = "linux")]
pub const SYSTEM_STATE_DIR: &str = "/var/lib/stt-guard";
#[cfg(not(any(target_os = "macos", target_os = "linux")))]
pub const SYSTEM_STATE_DIR: &str = "/var/lib/stt-guard";

/// System-wide log directory.
#[cfg(target_os = "macos")]
pub const SYSTEM_LOG_DIR: &str = "/var/log/stt-guard";
#[cfg(target_os = "linux")]
pub const SYSTEM_LOG_DIR: &str = "/var/log/stt-guard";
#[cfg(not(any(target_os = "macos", target_os = "linux")))]
pub const SYSTEM_LOG_DIR: &str = "/var/log/stt-guard";

/// Binary install directory (root:wheel 755).
pub const SYSTEM_BIN_DIR: &str = "/usr/local/libexec/stt-guard";

// ---------------------------------------------------------------------------
// Filenames (joined onto a state_dir / log_dir)
// ---------------------------------------------------------------------------

pub const DB_FILENAME: &str = "stt-guard.db";
pub const SOCKET_FILENAME: &str = "stt-guard-daemon.sock";
pub const LOG_FILENAME: &str = "stt-guard.log";
pub const READY_FILENAME: &str = "daemon.ready";
pub const HOOK_HASH_FILENAME: &str = "hook.sha256";
pub const TRUSTED_RULE_SIGNERS_FILENAME: &str = "trusted-rule-signers.tsv";
pub const MANIFEST_FILENAME: &str = "snapshot.manifest";
pub const WATCHDOG_STATE_FILENAME: &str = "watchdog.state";
pub const RUNS_DIR_NAME: &str = "runs";

/// Rotated-log filename prefix (e.g. `stt-guard-2024-01-15.log.gz`).
pub const ROTATED_LOG_PREFIX: &str = "stt-guard-";
pub const ROTATED_LOG_SUFFIX_GZ: &str = ".log.gz";

// ---------------------------------------------------------------------------
// Binary / hook library names
// ---------------------------------------------------------------------------

pub const CLI_BIN: &str = "stt-guard";
pub const DAEMON_BIN: &str = "stt-guard-daemon";

#[cfg(target_os = "macos")]
pub const HOOK_LIBRARY: &str = "stt-guard-hook.dylib";
#[cfg(target_os = "linux")]
pub const HOOK_LIBRARY: &str = "stt-guard-hook.so";
#[cfg(not(any(target_os = "macos", target_os = "linux")))]
pub const HOOK_LIBRARY: &str = "stt-guard-hook";

/// Backward-compatible alias for macOS-era call sites. New code should use
/// `HOOK_LIBRARY` when the value is not specifically about a Mach-O dylib.
pub const HOOK_DYLIB: &str = HOOK_LIBRARY;

pub const WATCHDOG_BIN: &str = "stt-guard-watchdog";

pub const INSTALLED_BINARIES: &[&str] = &[CLI_BIN, DAEMON_BIN, WATCHDOG_BIN];

#[cfg(target_os = "macos")]
pub const SYSTEM_HOOK_PATH: &str = "/usr/local/libexec/stt-guard/stt-guard-hook.dylib";
#[cfg(target_os = "linux")]
pub const SYSTEM_HOOK_PATH: &str = "/usr/local/libexec/stt-guard/stt-guard-hook.so";
#[cfg(not(any(target_os = "macos", target_os = "linux")))]
pub const SYSTEM_HOOK_PATH: &str = "/usr/local/libexec/stt-guard/stt-guard-hook";

// ---------------------------------------------------------------------------
// LaunchDaemon
// ---------------------------------------------------------------------------

pub const PLIST_LABEL: &str = "io.stentorian.guard.daemon";
pub const PLIST_PATH: &str = "/Library/LaunchDaemons/io.stentorian.guard.daemon.plist";

// ---------------------------------------------------------------------------
// Service user (hardened install)
// ---------------------------------------------------------------------------

pub const SERVICE_USER: &str = "_stt_guard";
pub const SERVICE_USER_REALNAME: &str = "Stentorian Guard Daemon";

// ---------------------------------------------------------------------------
// Environment variable names
// ---------------------------------------------------------------------------

pub const ENV_STATE_DIR: &str = "STT_GUARD_STATE_DIR";
pub const ENV_HOOK_LIBRARY: &str = "STT_GUARD_HOOK_DYLIB";
/// Backward-compatible name for the development hook-library override.
pub const ENV_HOOK_DYLIB: &str = ENV_HOOK_LIBRARY;
pub const ENV_SNAPSHOT_MANIFEST: &str = "STT_GUARD_SNAPSHOT_MANIFEST";

#[cfg(target_os = "macos")]
pub const ENV_HOOK_INJECTION: &str = "DYLD_INSERT_LIBRARIES";
#[cfg(target_os = "linux")]
pub const ENV_HOOK_INJECTION: &str = "LD_PRELOAD";
#[cfg(not(any(target_os = "macos", target_os = "linux")))]
pub const ENV_HOOK_INJECTION: &str = "LD_PRELOAD";

/// Backward-compatible alias for macOS-era call sites. New code should use
/// `ENV_HOOK_INJECTION` when the value is platform-specific.
pub const ENV_DYLD: &str = ENV_HOOK_INJECTION;

// ---------------------------------------------------------------------------
// Path builders (all derive from a state_dir root)
// ---------------------------------------------------------------------------

pub fn db_path(state_dir: &Path) -> PathBuf {
    state_dir.join(DB_FILENAME)
}

pub fn socket_path(state_dir: &Path) -> PathBuf {
    state_dir.join(SOCKET_FILENAME)
}

pub fn ready_path(state_dir: &Path) -> PathBuf {
    state_dir.join(READY_FILENAME)
}

pub fn manifest_path(state_dir: &Path) -> PathBuf {
    state_dir.join(MANIFEST_FILENAME)
}

pub fn manifest_tmp_path(state_dir: &Path) -> PathBuf {
    state_dir.join(format!(".{MANIFEST_FILENAME}.tmp"))
}

pub fn hook_hash_path(state_dir: &Path) -> PathBuf {
    state_dir.join(HOOK_HASH_FILENAME)
}

pub fn trusted_rule_signers_path() -> PathBuf {
    PathBuf::from(SYSTEM_BIN_DIR).join(TRUSTED_RULE_SIGNERS_FILENAME)
}

pub fn snapshot_path(state_dir: &Path, nonce: u64) -> PathBuf {
    state_dir.join(format!("snapshot-{nonce:016x}.cbor"))
}

pub fn snapshot_tmp_path(state_dir: &Path, nonce: u64) -> PathBuf {
    state_dir.join(format!(".snapshot-{nonce:016x}.cbor.tmp"))
}

pub fn watchdog_state_path(state_dir: &Path) -> PathBuf {
    state_dir.join(WATCHDOG_STATE_FILENAME)
}

// --- Per-run paths ---

pub fn runs_dir(state_dir: &Path) -> PathBuf {
    state_dir.join(RUNS_DIR_NAME)
}

pub fn run_snapshot_path(state_dir: &Path, run_uuid: &str) -> PathBuf {
    runs_dir(state_dir).join(format!("{run_uuid}.cbor"))
}

pub fn run_snapshot_tmp_path(state_dir: &Path, run_uuid: &str) -> PathBuf {
    runs_dir(state_dir).join(format!(".{run_uuid}.cbor.tmp"))
}

pub fn run_manifest_path(state_dir: &Path, run_uuid: &str) -> PathBuf {
    runs_dir(state_dir).join(format!("{run_uuid}.manifest"))
}

pub fn run_manifest_tmp_path(state_dir: &Path, run_uuid: &str) -> PathBuf {
    runs_dir(state_dir).join(format!(".{run_uuid}.manifest.tmp"))
}

// --- State dir resolution ---

pub fn is_system_install(state_dir: &Path) -> bool {
    state_dir == Path::new(SYSTEM_STATE_DIR)
}

/// Resolve the default state directory.
///
/// Priority: `STT_GUARD_STATE_DIR` env override → system dir (if exists) →
/// platform user-level state directory.
pub fn default_state_dir() -> PathBuf {
    if let Some(dir) = std::env::var_os(ENV_STATE_DIR) {
        return PathBuf::from(dir);
    }
    let sys = PathBuf::from(SYSTEM_STATE_DIR);
    if sys.exists() {
        return sys;
    }
    user_state_dir()
}

/// User-level log directory (used when not running as system install).
pub fn user_log_dir() -> PathBuf {
    #[cfg(target_os = "macos")]
    {
        let home = home_dir_from_env();
        home.join("Library/Logs/Stentorian Guard")
    }

    #[cfg(target_os = "linux")]
    {
        user_state_dir().join("logs")
    }

    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        user_state_dir().join("logs")
    }
}

fn user_state_dir() -> PathBuf {
    #[cfg(target_os = "macos")]
    {
        home_dir_from_env().join("Library/Application Support/Stentorian Guard")
    }

    #[cfg(target_os = "linux")]
    {
        linux_user_state_dir(
            std::env::var_os("HOME").as_deref(),
            std::env::var_os("XDG_STATE_HOME").as_deref(),
        )
    }

    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        home_dir_from_env().join(".local/state/stt-guard")
    }
}

#[cfg(not(target_os = "linux"))]
fn home_dir_from_env() -> PathBuf {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .expect("HOME environment variable must be set")
}

#[cfg(target_os = "linux")]
fn linux_user_state_dir(
    home: Option<&std::ffi::OsStr>,
    xdg_state_home: Option<&std::ffi::OsStr>,
) -> PathBuf {
    if let Some(xdg_state_home) = xdg_state_home.filter(|value| !value.is_empty()) {
        return PathBuf::from(xdg_state_home).join("stt-guard");
    }

    let home = home
        .map(PathBuf::from)
        .expect("HOME environment variable must be set");
    home.join(".local/state/stt-guard")
}

/// Runtime JSONL log directory for a daemon using `state_dir`.
pub fn log_dir_for_state(state_dir: &Path) -> PathBuf {
    if is_system_install(state_dir) {
        PathBuf::from(SYSTEM_LOG_DIR)
    } else {
        user_log_dir()
    }
}

/// Ensure `state_dir` exists with mode 0700. Idempotent.
pub fn ensure_state_dir(state_dir: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::DirBuilderExt;
    if state_dir.exists() {
        return Ok(());
    }
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(state_dir)
}

/// Ensure `runs/` subdirectory exists with mode 0711. Idempotent.
///
/// Per-run snapshot artifacts under this directory are read-only, signed policy
/// inputs for wrapped user processes. The directory is searchable but not
/// listable so a wrapped process can open the exact manifest path handed to it
/// without exposing mutable daemon state.
pub fn ensure_runs_dir(state_dir: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::DirBuilderExt;
    use std::os::unix::fs::PermissionsExt;
    let dir = runs_dir(state_dir);
    if !dir.exists() {
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o711)
            .create(&dir)?;
    }
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o711))
}

// ---------------------------------------------------------------------------
// Thread names (daemon internal)
// ---------------------------------------------------------------------------

pub const THREAD_PERSIST_WATCH: &str = "stt-guard-daemon-persist-watch";
pub const THREAD_LOG_WRITER: &str = "stt-guard-daemon-log-writer";
pub const THREAD_LOG_ROTATE: &str = "stt-guard-daemon-log-rotate";
pub const THREAD_SNAPSHOT_GC: &str = "stt-guard-daemon-gc";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn is_system_install_true_for_system_path() {
        assert!(is_system_install(Path::new(SYSTEM_STATE_DIR)));
    }

    #[test]
    fn is_system_install_false_for_user_path() {
        assert!(!is_system_install(Path::new(
            "/Users/someone/Library/Application Support/Stentorian Guard"
        )));
    }

    #[test]
    fn is_system_install_false_for_tmpdir() {
        let tmp = tempfile::tempdir().unwrap();
        assert!(!is_system_install(tmp.path()));
    }

    #[test]
    fn db_path_joins_correctly() {
        let p = db_path(Path::new("/tmp/test"));
        assert_eq!(p, PathBuf::from("/tmp/test/stt-guard.db"));
    }

    #[test]
    fn socket_path_joins_correctly() {
        let p = socket_path(Path::new("/tmp/test"));
        assert_eq!(p, PathBuf::from("/tmp/test/stt-guard-daemon.sock"));
    }

    #[test]
    fn snapshot_path_format() {
        let p = snapshot_path(Path::new("/s"), 42);
        assert_eq!(p, PathBuf::from("/s/snapshot-000000000000002a.cbor"));
    }

    #[test]
    fn run_paths_nest_under_runs() {
        let p = run_manifest_path(Path::new("/s"), "abc-123");
        assert_eq!(p, PathBuf::from("/s/runs/abc-123.manifest"));
    }

    #[test]
    #[cfg(target_os = "macos")]
    fn hook_constants_are_macos_specific() {
        assert_eq!(HOOK_LIBRARY, "stt-guard-hook.dylib");
        assert_eq!(ENV_HOOK_INJECTION, "DYLD_INSERT_LIBRARIES");
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn hook_constants_are_linux_specific() {
        assert_eq!(HOOK_LIBRARY, "stt-guard-hook.so");
        assert_eq!(ENV_HOOK_INJECTION, "LD_PRELOAD");
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn linux_user_state_dir_uses_xdg_state_home() {
        let path = linux_user_state_dir(Some("/home/dev".as_ref()), Some("/tmp/state".as_ref()));

        assert_eq!(path, PathBuf::from("/tmp/state/stt-guard"));
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn linux_user_state_dir_falls_back_to_home_local_state() {
        let path = linux_user_state_dir(Some("/home/dev".as_ref()), None);

        assert_eq!(path, PathBuf::from("/home/dev/.local/state/stt-guard"));
    }
}
