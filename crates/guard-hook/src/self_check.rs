//! Hook binary self-integrity verification (M004-S03).
//!
//! At ctor time, the hook computes SHA-256 of its own dylib file and compares
//! it against the expected hash stored in `state_dir/hook.sha256`. If the hash
//! doesn't match, FAIL_CLOSED is set.
//!
//! The expected hash file is written at install time by the CLI.

use sha2::{Digest, Sha256};
use std::ffi::CStr;
use std::fs::OpenOptions;
use std::io::Read;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use guard_core::paths::HOOK_HASH_FILENAME as HASH_FILENAME;

#[derive(Debug)]
pub enum SelfCheckError {
    DylibPathUnknown,
    HashFileNotFound,
    HashFileMalformed,
    DylibOpenFailed(String),
    DigestMismatch { expected: String, got: String },
    Io(std::io::Error),
}

/// Discover the on-disk path of this dylib using dladdr on an internal symbol.
fn dylib_path() -> Option<PathBuf> {
    let mut info: libc::Dl_info = unsafe { std::mem::zeroed() };
    let ret = unsafe {
        libc::dladdr(
            guard_hook_self_check_anchor as *const extern "C" fn() as *mut libc::c_void,
            &mut info,
        )
    };
    if ret == 0 || info.dli_fname.is_null() {
        return None;
    }
    let path_str = unsafe { CStr::from_ptr(info.dli_fname) };
    Some(PathBuf::from(path_str.to_string_lossy().into_owned()))
}

/// Verify the hook's binary integrity against the stored hash.
/// Returns Ok(()) if verification passes or if no hash file exists (graceful
/// degradation for installations that predate M004-S03).
/// Returns Err on tamper detection.
pub fn verify(state_dir: &Path) -> Result<(), SelfCheckError> {
    let hash_path = state_dir.join(HASH_FILENAME);
    if !hash_path.exists() {
        return Ok(());
    }

    let expected = std::fs::read_to_string(&hash_path)
        .map_err(SelfCheckError::Io)?
        .trim()
        .to_string();
    if expected.len() != 64 || !expected.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(SelfCheckError::HashFileMalformed);
    }

    let lib_path = dylib_path().ok_or(SelfCheckError::DylibPathUnknown)?;
    let mut f = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&lib_path)
        .map_err(|e| SelfCheckError::DylibOpenFailed(format!("{}: {e}", lib_path.display())))?;

    let mut hasher = Sha256::new();
    let mut buf = [0u8; 8192];
    loop {
        let n = f.read(&mut buf).map_err(SelfCheckError::Io)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    let computed = format!("{:x}", hasher.finalize());

    if computed != expected {
        return Err(SelfCheckError::DigestMismatch {
            expected,
            got: computed,
        });
    }
    Ok(())
}

/// Anchor symbol used by dladdr to locate this dylib.
#[unsafe(no_mangle)]
pub extern "C" fn guard_hook_self_check_anchor() {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verify_returns_ok_when_no_hash_file() {
        let tmp = tempfile::tempdir().unwrap();
        assert!(verify(tmp.path()).is_ok());
    }

    #[test]
    fn verify_returns_error_on_malformed_hash_file() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join(HASH_FILENAME), "not-a-hash\n").unwrap();
        let r = verify(tmp.path());
        assert!(matches!(r, Err(SelfCheckError::HashFileMalformed)));
    }

    #[test]
    fn dylib_path_returns_some() {
        let p = dylib_path();
        assert!(p.is_some(), "dladdr should resolve our own dylib path");
    }
}
