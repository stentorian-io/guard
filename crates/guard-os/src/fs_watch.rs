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
    use super::*;

    pub struct WatchSet {
        kq: RawFd,
        eventlist: Vec<libc::kevent>,
    }

    impl WatchSet {
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

        pub fn add(&self, fd: RawFd) -> Result<(), OsError> {
            let kev = libc::kevent {
                ident: fd as usize,
                filter: libc::EVFILT_VNODE,
                flags: libc::EV_ADD | libc::EV_CLEAR,
                fflags: libc::NOTE_WRITE | libc::NOTE_EXTEND,
                data: 0,
                udata: std::ptr::null_mut(),
            };
            let ret = unsafe {
                libc::kevent(self.kq, &kev, 1, std::ptr::null_mut(), 0, std::ptr::null())
            };
            if ret < 0 {
                return Err(OsError::io(
                    "filesystem watch add",
                    std::io::Error::last_os_error(),
                ));
            }
            Ok(())
        }

        pub fn add_many(&self, fds: impl IntoIterator<Item = RawFd>) -> Result<(), OsError> {
            let changelist: Vec<libc::kevent> = fds
                .into_iter()
                .map(|fd| libc::kevent {
                    ident: fd as usize,
                    filter: libc::EVFILT_VNODE,
                    flags: libc::EV_ADD | libc::EV_CLEAR,
                    fflags: libc::NOTE_WRITE | libc::NOTE_EXTEND,
                    data: 0,
                    udata: std::ptr::null_mut(),
                })
                .collect();
            if changelist.is_empty() {
                return Ok(());
            }
            let ret = unsafe {
                libc::kevent(
                    self.kq,
                    changelist.as_ptr(),
                    changelist.len() as i32,
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

        pub fn wait(&mut self, timeout_secs: i64) -> Result<WatchEvent, OsError> {
            let timeout = libc::timespec {
                tv_sec: timeout_secs,
                tv_nsec: 0,
            };
            let n = unsafe {
                libc::kevent(
                    self.kq,
                    std::ptr::null(),
                    0,
                    self.eventlist.as_mut_ptr(),
                    self.eventlist.len() as i32,
                    &timeout,
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
            Ok(WatchEvent::Fds(
                self.eventlist[..n as usize]
                    .iter()
                    .map(|ev| ev.ident as RawFd)
                    .collect(),
            ))
        }
    }

    impl Drop for WatchSet {
        fn drop(&mut self) {
            unsafe { libc::close(self.kq) };
        }
    }

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
    use super::*;

    pub struct WatchSet;

    impl WatchSet {
        pub fn new() -> Result<Self, OsError> {
            Err(OsError::unsupported("filesystem watch"))
        }

        pub fn add(&self, _fd: RawFd) -> Result<(), OsError> {
            Err(OsError::unsupported("filesystem watch"))
        }

        pub fn add_many(&self, _fds: impl IntoIterator<Item = RawFd>) -> Result<(), OsError> {
            Err(OsError::unsupported("filesystem watch"))
        }

        pub fn wait(&mut self, _timeout_secs: i64) -> Result<WatchEvent, OsError> {
            Err(OsError::unsupported("filesystem watch"))
        }
    }

    pub fn open_dir_for_events(_path: &Path) -> Result<RawFd, OsError> {
        Err(OsError::unsupported("filesystem watch"))
    }
}

pub use imp::WatchSet;

pub fn open_dir_for_events(path: &Path) -> Result<RawFd, OsError> {
    imp::open_dir_for_events(path)
}
