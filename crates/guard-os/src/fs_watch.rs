//! Filesystem watch primitives.

use crate::OsError;
use std::os::unix::io::RawFd;
use std::path::Path;

#[derive(Debug)]
pub enum WatchEvent {
    Timeout,
    Fds(Vec<RawFd>),
}

#[cfg(target_os = "macos")]
mod imp {
    use super::{OsError, Path, RawFd, WatchEvent};

    pub struct WatchSet {
        kq: RawFd,
        eventlist: Vec<libc::kevent>,
    }

    impl WatchSet {
        /// Create a new filesystem watch set.
        ///
        /// # Errors
        ///
        /// Returns an OS error if `kqueue` cannot be created.
        pub fn new() -> Result<Self, OsError> {
            let kq = unsafe { libc::kqueue() };
            if kq < 0 {
                return Err(OsError::io(
                    "filesystem watch",
                    std::io::Error::last_os_error(),
                ));
            }
            Ok(Self {
                kq,
                eventlist: vec![unsafe { std::mem::zeroed::<libc::kevent>() }; 16],
            })
        }

        /// Add one file descriptor to the watch set.
        ///
        /// # Errors
        ///
        /// Returns an OS error if the descriptor is invalid or `kevent` fails.
        pub fn add(&self, fd: RawFd) -> Result<(), OsError> {
            let ident = usize::try_from(fd).map_err(|_| {
                OsError::unexpected_data("filesystem watch add", format!("invalid fd {fd}"))
            })?;
            let kev = libc::kevent {
                ident,
                filter: libc::EVFILT_VNODE,
                flags: libc::EV_ADD | libc::EV_CLEAR,
                fflags: libc::NOTE_WRITE | libc::NOTE_EXTEND,
                data: 0,
                udata: std::ptr::null_mut(),
            };
            let ret = unsafe {
                libc::kevent(
                    self.kq,
                    &raw const kev,
                    1,
                    std::ptr::null_mut(),
                    0,
                    std::ptr::null(),
                )
            };
            if ret < 0 {
                return Err(OsError::io(
                    "filesystem watch add",
                    std::io::Error::last_os_error(),
                ));
            }
            Ok(())
        }

        /// Add several file descriptors to the watch set.
        ///
        /// # Errors
        ///
        /// Returns an OS error if any descriptor is invalid, too many
        /// descriptors are added in one call, or `kevent` fails.
        pub fn add_many(&self, fds: impl IntoIterator<Item = RawFd>) -> Result<(), OsError> {
            let changelist: Result<Vec<libc::kevent>, OsError> = fds
                .into_iter()
                .map(|fd| {
                    let ident = usize::try_from(fd).map_err(|_| {
                        OsError::unexpected_data("filesystem watch add", format!("invalid fd {fd}"))
                    })?;

                    Ok(libc::kevent {
                        ident,
                        filter: libc::EVFILT_VNODE,
                        flags: libc::EV_ADD | libc::EV_CLEAR,
                        fflags: libc::NOTE_WRITE | libc::NOTE_EXTEND,
                        data: 0,
                        udata: std::ptr::null_mut(),
                    })
                })
                .collect();
            let changelist = changelist?;
            if changelist.is_empty() {
                return Ok(());
            }
            let changelist_len = i32::try_from(changelist.len()).map_err(|_| {
                OsError::unexpected_data("filesystem watch add", "too many descriptors")
            })?;
            let ret = unsafe {
                libc::kevent(
                    self.kq,
                    changelist.as_ptr(),
                    changelist_len,
                    std::ptr::null_mut(),
                    0,
                    std::ptr::null(),
                )
            };
            if ret < 0 {
                return Err(OsError::io(
                    "filesystem watch add",
                    std::io::Error::last_os_error(),
                ));
            }
            Ok(())
        }

        /// Wait for filesystem events.
        ///
        /// # Errors
        ///
        /// Returns an OS error if `kevent` fails for a reason other than `EINTR`,
        /// or if a returned descriptor cannot fit `RawFd`.
        pub fn wait(&mut self, timeout_secs: i64) -> Result<WatchEvent, OsError> {
            let timeout = libc::timespec {
                tv_sec: timeout_secs,
                tv_nsec: 0,
            };
            let eventlist_len = i32::try_from(self.eventlist.len()).map_err(|_| {
                OsError::unexpected_data("filesystem watch wait", "event list too large")
            })?;
            let n = unsafe {
                libc::kevent(
                    self.kq,
                    std::ptr::null(),
                    0,
                    self.eventlist.as_mut_ptr(),
                    eventlist_len,
                    &raw const timeout,
                )
            };
            if n < 0 {
                let err = std::io::Error::last_os_error();
                if err.raw_os_error() == Some(libc::EINTR) {
                    return Ok(WatchEvent::Fds(Vec::new()));
                }
                return Err(OsError::io("filesystem watch wait", err));
            }
            if n == 0 {
                return Ok(WatchEvent::Timeout);
            }
            let event_count = usize::try_from(n).map_err(|_| {
                OsError::unexpected_data("filesystem watch wait", "invalid event count")
            })?;
            let fds = self.eventlist[..event_count]
                .iter()
                .map(|ev| {
                    let ident = unsafe { std::ptr::read_unaligned(&raw const ev.ident) };

                    RawFd::try_from(ident).map_err(|_| {
                        OsError::unexpected_data(
                            "filesystem watch wait",
                            format!("event ident does not fit RawFd: {ident}"),
                        )
                    })
                })
                .collect::<Result<Vec<_>, _>>()?;

            Ok(WatchEvent::Fds(fds))
        }
    }

    impl Drop for WatchSet {
        fn drop(&mut self) {
            unsafe { libc::close(self.kq) };
        }
    }

    /// Open a directory file descriptor suitable for filesystem events.
    ///
    /// # Errors
    ///
    /// Returns an OS error if the path cannot be represented as a C string or
    /// the directory cannot be opened.
    pub fn open_dir_for_events(path: &Path) -> Result<RawFd, OsError> {
        let c_path = std::ffi::CString::new(path.to_string_lossy().as_bytes())
            .map_err(|e| OsError::unexpected_data("filesystem watch path", e.to_string()))?;
        let fd = unsafe { libc::open(c_path.as_ptr(), libc::O_RDONLY | libc::O_EVTONLY) };
        if fd < 0 {
            return Err(OsError::io(
                "filesystem watch open",
                std::io::Error::last_os_error(),
            ));
        }
        Ok(fd)
    }
}

#[cfg(not(target_os = "macos"))]
mod imp {
    use super::{OsError, Path, RawFd, WatchEvent};

    pub struct WatchSet;

    impl WatchSet {
        /// Create a new filesystem watch set.
        ///
        /// # Errors
        ///
        /// Always returns unsupported on this platform.
        pub fn new() -> Result<Self, OsError> {
            Err(OsError::unsupported("filesystem watch"))
        }

        /// Add one file descriptor to the watch set.
        ///
        /// # Errors
        ///
        /// Always returns unsupported on this platform.
        pub fn add(&self, _fd: RawFd) -> Result<(), OsError> {
            Err(OsError::unsupported("filesystem watch"))
        }

        /// Add several file descriptors to the watch set.
        ///
        /// # Errors
        ///
        /// Always returns unsupported on this platform.
        pub fn add_many(&self, _fds: impl IntoIterator<Item = RawFd>) -> Result<(), OsError> {
            Err(OsError::unsupported("filesystem watch"))
        }

        /// Wait for filesystem events.
        ///
        /// # Errors
        ///
        /// Always returns unsupported on this platform.
        pub fn wait(&mut self, _timeout_secs: i64) -> Result<WatchEvent, OsError> {
            Err(OsError::unsupported("filesystem watch"))
        }
    }

    pub fn open_dir_for_events(_path: &Path) -> Result<RawFd, OsError> {
        Err(OsError::unsupported("filesystem watch"))
    }
}

pub use imp::WatchSet;

/// Open a directory file descriptor suitable for filesystem events.
///
/// # Errors
///
/// Returns an OS error from the platform implementation.
pub fn open_dir_for_events(path: &Path) -> Result<RawFd, OsError> {
    imp::open_dir_for_events(path)
}
