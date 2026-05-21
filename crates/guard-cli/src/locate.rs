//! Resolve the absolute path to stt-guard-hook.dylib.
//!
//! Discovery order:
//!   1. `STT_GUARD_HOOK_DYLIB` override
//!   2. Sibling of CLI binary at `target/{debug,release}/stt-guard-hook.dylib`
//!   3. Any sibling hook dylib emitted by local development builds
//!   4. System install path (`/usr/local/libexec/stt-guard/`)
//!   5. Hardcoded Homebrew path

use std::path::PathBuf;

use guard_core::paths::{
    ENV_HOOK_DYLIB, HOMEBREW_HOOK_PATH as HOMEBREW_RELEASE_PATH, HOOK_DYLIB as DYLIB_NAME,
    SYSTEM_HOOK_PATH as SYSTEM_INSTALL_PATH,
};

pub fn find_dylib() -> std::io::Result<PathBuf> {
    // 1. Explicit override for source builds and tests.
    if let Some(path) = std::env::var_os(ENV_HOOK_DYLIB) {
        let candidate = PathBuf::from(path);
        if candidate.exists() {
            return candidate.canonicalize();
        }
        return Err(std::io::Error::other(format!(
            "{ENV_HOOK_DYLIB} points to missing dylib: {}",
            candidate.display()
        )));
    }

    // 2. Sibling of CLI binary (dev-mode: target/debug/ or target/release/).
    let exe = std::env::current_exe()?;
    if let Some(parent) = exe.parent() {
        let candidate = parent.join(DYLIB_NAME);
        if candidate.exists() {
            return candidate.canonicalize();
        }
        if let Ok(entries) = std::fs::read_dir(parent) {
            for entry in entries.flatten() {
                let path = entry.path();
                let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
                    continue;
                };
                if name.ends_with(".dylib") && name.contains("hook") {
                    return path.canonicalize();
                }
            }
        }
    }

    // 4. System install path (hardened deployment).
    let system = PathBuf::from(SYSTEM_INSTALL_PATH);
    if system.exists() {
        return system.canonicalize();
    }

    // 5. Homebrew path.
    let release = PathBuf::from(HOMEBREW_RELEASE_PATH);
    if release.exists() {
        return release.canonicalize();
    }

    Err(std::io::Error::other(format!(
        "could not find {DYLIB_NAME}: tried {ENV_HOOK_DYLIB}, sibling-of-CLI, sibling hook dylibs, {SYSTEM_INSTALL_PATH}, and {HOMEBREW_RELEASE_PATH}"
    )))
}
