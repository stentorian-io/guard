//! Resolve the absolute path to stt-guard-hook.dylib.
//!
//! Hardened production mode is deliberately strict: once no explicit test state
//! directory is selected, the hook must come from the root-owned system install
//! path verified by the install gate. Development discovery is only enabled
//! when `STT_GUARD_STATE_DIR` is set.

use std::path::PathBuf;

use guard_core::paths::{
    ENV_HOOK_DYLIB, ENV_STATE_DIR, HOOK_DYLIB as DYLIB_NAME,
    SYSTEM_HOOK_PATH as SYSTEM_INSTALL_PATH,
};

pub fn find_dylib() -> std::io::Result<PathBuf> {
    let dev_mode = std::env::var_os(ENV_STATE_DIR).is_some();

    if !dev_mode {
        let system = PathBuf::from(SYSTEM_INSTALL_PATH);
        if system.exists() {
            return system.canonicalize();
        }
        return Err(std::io::Error::other(format!(
            "hardened install is missing {SYSTEM_INSTALL_PATH}; run: sudo stt-guard init"
        )));
    }

    // Development/test override for source builds and harnesses only.
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

    // Sibling of CLI binary (dev-mode: target/debug/ or target/release/).
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

    Err(std::io::Error::other(format!(
        "could not find {DYLIB_NAME}: in dev/test mode tried {ENV_HOOK_DYLIB}, sibling-of-CLI, and sibling hook dylibs"
    )))
}
