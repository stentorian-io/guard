//! OS errno access.

#[cfg(target_os = "macos")]
pub fn last_errno() -> i32 {
    unsafe { *libc::__error() }
}

#[cfg(not(target_os = "macos"))]
pub fn last_errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
}

#[cfg(target_os = "macos")]
pub fn set_errno(errno: i32) {
    unsafe {
        *libc::__error() = errno;
    }
}

#[cfg(not(target_os = "macos"))]
pub fn set_errno(_errno: i32) {}
