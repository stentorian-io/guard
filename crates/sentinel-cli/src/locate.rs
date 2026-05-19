//! Resolve the absolute path to libsentinel_hook.dylib.
//!
//! Discovery order:
//!   1. Sibling of CLI binary at `target/{debug,release}/libsentinel_hook.dylib`
//!   2. Hardcoded Homebrew path

use std::path::PathBuf;

const DYLIB_NAME: &str = "libsentinel_hook.dylib";
const HOMEBREW_RELEASE_PATH: &str = "/opt/homebrew/lib/sentinel/libsentinel_hook.dylib";

pub fn find_dylib() -> std::io::Result<PathBuf> {
    // 1. Sibling of CLI binary (dev-mode: target/debug/ or target/release/).
    let exe = std::env::current_exe()?;
    if let Some(parent) = exe.parent() {
        let candidate = parent.join(DYLIB_NAME);
        if candidate.exists() {
            return candidate.canonicalize();
        }
    }

    // 2. Homebrew path.
    let release = PathBuf::from(HOMEBREW_RELEASE_PATH);
    if release.exists() {
        return release.canonicalize();
    }

    Err(std::io::Error::other(format!(
        "could not find {DYLIB_NAME}: tried sibling-of-CLI and {HOMEBREW_RELEASE_PATH}"
    )))
}
