//! Resolve the absolute path to the platform hook library.
//!
//! Hardened production mode is deliberately strict: once no explicit test state
//! directory is selected, the hook must come from the root-owned system install
//! path verified by the install gate. Development discovery is only enabled
//! when `STT_GUARD_STATE_DIR` is set.

use std::path::PathBuf;

use guard_core::paths::{
    ENV_HOOK_LIBRARY, ENV_STATE_DIR, HOOK_LIBRARY as HOOK_LIBRARY_NAME,
    SYSTEM_HOOK_PATH as SYSTEM_INSTALL_PATH,
};

/// Locate the hook dynamic library for production or development mode.
///
/// # Errors
///
/// Returns an error when the required production hook is absent, an override is
/// invalid, or no development hook can be found next to the CLI.
pub fn find_dylib() -> std::io::Result<PathBuf> {
    let dev_mode = std::env::var_os(ENV_STATE_DIR).is_some();

    if !dev_mode {
        let system = PathBuf::from(SYSTEM_INSTALL_PATH);
        if system.exists() {
            return system.canonicalize();
        }
        return Err(std::io::Error::other(format!(
            "hardened install is missing {SYSTEM_INSTALL_PATH}; run the installer or stt-guard update"
        )));
    }

    // Development/test override for source builds and harnesses only.
    if let Some(path) = std::env::var_os(ENV_HOOK_LIBRARY) {
        let candidate = PathBuf::from(path);
        if candidate.exists() {
            return candidate.canonicalize();
        }
        return Err(std::io::Error::other(format!(
            "{ENV_HOOK_LIBRARY} points to missing hook library: {}",
            candidate.display()
        )));
    }

    // Sibling of CLI binary (dev-mode: target/debug/ or target/release/).
    let exe = std::env::current_exe()?;
    if let Some(parent) = exe.parent() {
        let candidate = parent.join(HOOK_LIBRARY_NAME);
        if candidate.exists() {
            return candidate.canonicalize();
        }
        if let Ok(entries) = std::fs::read_dir(parent) {
            for entry in entries.flatten() {
                let path = entry.path();
                let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
                    continue;
                };
                if hook_library_filename_matches(name) {
                    return path.canonicalize();
                }
            }
        }
    }

    Err(std::io::Error::other(format!(
        "could not find {HOOK_LIBRARY_NAME}: in dev/test mode tried {ENV_HOOK_LIBRARY}, sibling-of-CLI, and sibling hook libraries"
    )))
}

fn hook_library_filename_matches(name: &str) -> bool {
    name.contains("hook") && platform_hook_extension_matches(name)
}

#[cfg(target_os = "macos")]
fn platform_hook_extension_matches(name: &str) -> bool {
    std::path::Path::new(name)
        .extension()
        .is_some_and(|ext| ext.eq_ignore_ascii_case("dylib"))
}

#[cfg(target_os = "linux")]
fn platform_hook_extension_matches(name: &str) -> bool {
    std::path::Path::new(name)
        .extension()
        .is_some_and(|ext| ext.eq_ignore_ascii_case("so"))
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
fn platform_hook_extension_matches(name: &str) -> bool {
    name.contains("hook")
}
