//! System information primitives.

/// Return the host macOS major version.
///
/// Non-macOS targets return the conservative default used by the persistence
/// classifier so callers can compile without treating Linux as supported.
pub fn macos_major_version() -> u32 {
    use std::sync::OnceLock;

    static VER: OnceLock<u32> = OnceLock::new();
    *VER.get_or_init(detect_macos_major)
}

#[cfg(target_os = "macos")]
fn detect_macos_major() -> u32 {
    let mut buf = [0u8; 32];
    let mut len = buf.len();
    let name = c"kern.osproductversion";
    let rc = unsafe {
        libc::sysctlbyname(
            name.as_ptr(),
            buf.as_mut_ptr() as *mut libc::c_void,
            &mut len,
            core::ptr::null_mut(),
            0,
        )
    };
    if rc != 0 || len == 0 {
        return 14;
    }
    let s = &buf[..len.saturating_sub(1)];
    let dot = s.iter().position(|&b| b == b'.').unwrap_or(s.len());
    let major_str = core::str::from_utf8(&s[..dot]).unwrap_or("14");
    major_str.parse().unwrap_or(14)
}

#[cfg(not(target_os = "macos"))]
fn detect_macos_major() -> u32 {
    14
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn macos_major_version_returns_nonzero_default() {
        assert!(macos_major_version() > 0);
    }
}
