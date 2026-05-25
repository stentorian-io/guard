//! OS errno access.

#[cfg(target_os = "macos")]
pub fn last_errno() -> i32 {
    unsafe { *libc::__error() }
}

#[cfg(target_os = "linux")]
pub fn last_errno() -> i32 {
    unsafe { *libc::__errno_location() }
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
pub fn last_errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
}

#[cfg(target_os = "macos")]
pub fn set_errno(errno: i32) {
    unsafe {
        *libc::__error() = errno;
    }
}

#[cfg(target_os = "linux")]
pub fn set_errno(errno: i32) {
    unsafe {
        *libc::__errno_location() = errno;
    }
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
pub fn set_errno(_errno: i32) {}

#[cfg(test)]
mod tests {
    use super::{last_errno, set_errno};

    #[test]
    fn set_errno_updates_last_errno() {
        set_errno(libc::EACCES);

        assert_eq!(last_errno(), libc::EACCES);
    }
}
