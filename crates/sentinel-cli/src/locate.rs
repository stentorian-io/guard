//! Resolve the absolute path to libsentinel_hook.dylib.
//!
//! v0.1 dev-mode order:
//!   1. SENTINEL_HOOK_DYLIB env var (highest priority — used by tests)
//!   2. Sibling of CLI binary at `target/{debug,release}/libsentinel_hook.dylib`
//!   3. Hardcoded Homebrew Cellar path (v0.5 release-mode default)

use std::path::PathBuf;

const DYLIB_NAME: &str = "libsentinel_hook.dylib";
const HOMEBREW_RELEASE_PATH: &str = "/opt/homebrew/lib/sentinel/libsentinel_hook.dylib";

pub fn find_dylib() -> std::io::Result<PathBuf> {
    // 1. Explicit env override — highest priority, used by integration tests.
    if let Some(p) = std::env::var_os("SENTINEL_HOOK_DYLIB") {
        let p = PathBuf::from(p);
        if p.exists() {
            return p.canonicalize();
        }
        return Err(std::io::Error::other(format!(
            "SENTINEL_HOOK_DYLIB={} does not exist",
            p.display()
        )));
    }

    // 2. Sibling of CLI binary (dev-mode: target/debug/ or target/release/).
    let exe = std::env::current_exe()?;
    if let Some(parent) = exe.parent() {
        let candidate = parent.join(DYLIB_NAME);
        if candidate.exists() {
            return candidate.canonicalize();
        }
    }

    // 3. Homebrew Cellar path (v0.5 release-mode default).
    let release = PathBuf::from(HOMEBREW_RELEASE_PATH);
    if release.exists() {
        return release.canonicalize();
    }

    Err(std::io::Error::other(format!(
        "could not find {DYLIB_NAME}: tried SENTINEL_HOOK_DYLIB, sibling-of-CLI, and {HOMEBREW_RELEASE_PATH}"
    )))
}
