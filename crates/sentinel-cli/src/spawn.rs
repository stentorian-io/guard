//! posix_spawnp wrapper. (RED stub)
use std::ffi::OsStr;
use std::path::Path;

pub fn spawn_wrapped(
    _program: &Path,
    _args: &[&OsStr],
    _dylib_path: &Path,
    _manifest_path: &Path,
) -> std::io::Result<libc::pid_t> {
    Err(std::io::Error::other("spawn_wrapped not yet implemented"))
}
