//! Resolve the absolute path to libsentinel_hook.dylib. (RED stub)
use std::path::PathBuf;

pub fn find_dylib() -> std::io::Result<PathBuf> {
    Err(std::io::Error::other("find_dylib not yet implemented"))
}
