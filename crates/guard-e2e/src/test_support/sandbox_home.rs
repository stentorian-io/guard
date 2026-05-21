//! Sandboxed HOME helper for v0.5 validation tests.
//!
//! Per CONTEXT D-02 triple-defense (3): every v0.5 test sets HOME to a
//! tempdir with empty .ssh/, .aws/, .npmrc and uses Command::new(...).env_clear()
//! so no real secrets exist on the test process or its descendants. Even a
//! complete Stentorian Guard enforcement failure would find nothing to exfiltrate.
//!
//! Extracts the tempdir + Stentorian Guard log directory pattern that lives inline today
//! in `DaemonHarness::start_with_env` and adds the empty-secret directories.

use std::io;
use std::path::Path;

/// A tempdir HOME with empty secret directories. Drop removes the tempdir.
pub struct SandboxHome {
    pub home: tempfile::TempDir,
}

impl SandboxHome {
    /// Convenience accessor for tests that want a borrowed Path.
    pub fn path(&self) -> &Path {
        self.home.path()
    }
}

/// Build a sandbox HOME with:
///   - `Library/Logs/Stentorian Guard/`  (Stentorian Guard's JSONL log directory)
///   - `.ssh/`                    (empty — defensive per D-02)
///   - `.aws/`                    (empty — defensive)
///   - `.npmrc`                   (empty file — npm reads but finds nothing)
///
/// Caller is responsible for using `.env_clear()` on every `Command::new(...)`
/// so no real `HOME`/`SSH_*`/`AWS_*`/`NPM_*` vars leak into the wrapped process.
pub fn create() -> io::Result<SandboxHome> {
    let home = tempfile::tempdir()?;
    let path = home.path();
    std::fs::create_dir_all(path.join("Library/Logs/Stentorian Guard"))?;
    std::fs::create_dir_all(path.join(".ssh"))?;
    std::fs::create_dir_all(path.join(".aws"))?;
    std::fs::write(path.join(".npmrc"), b"")?;
    Ok(SandboxHome { home })
}
