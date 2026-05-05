//! Snapshot loader: read manifest from env, verify path under state_dir,
//! verify SHA-256 digest, mmap, parse schema_version.
//!
//! On ANY error: fail-closed (returns Err; lib.rs sets FAIL_CLOSED = true).

use core::sync::atomic::AtomicBool;
use memmap2::Mmap;
use sha2::{Digest, Sha256};
use std::ffi::CStr;
use std::fs::OpenOptions;
use std::io::Read;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

pub static FAIL_CLOSED: AtomicBool = AtomicBool::new(false);

#[derive(Debug)]
pub enum LoadError {
    EnvUnset,
    PathOutsideStateDir { canonical: String, state_dir: String },
    OpenFailed(String),
    NotRegularFile(String),
    ManifestParseFailed,
    DigestMismatch { expected: String, got: String },
    SchemaMismatch { expected: u16, got: u16 },
    Io(std::io::Error),
    Codec(String),
}

pub struct LoadedSnapshot {
    pub _mmap: Mmap,                          // borrowed by entries; keep alive
    pub entries: Vec<sentinel_core::AllowlistEntry>,
    pub schema_version: u16,
    pub snapshot_path: PathBuf,
}

impl std::fmt::Debug for LoadedSnapshot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LoadedSnapshot")
            .field("schema_version", &self.schema_version)
            .field("snapshot_path", &self.snapshot_path)
            .field("entries_len", &self.entries.len())
            .finish()
    }
}

/// Phase 1 well-known state_dir for path validation. Must match plan 05.
fn well_known_state_dir() -> PathBuf {
    let home = std::env::var_os("HOME").unwrap_or_default();
    PathBuf::from(home).join("Library/Application Support/Sentinel")
}

/// Read SENTINEL_SNAPSHOT_MANIFEST via libc::getenv to avoid std::env::var
/// allocation in ctor (Pitfall 4). Returns None if unset.
unsafe fn getenv_libc(name: &CStr) -> Option<String> {
    let p = unsafe { libc::getenv(name.as_ptr()) };
    if p.is_null() {
        return None;
    }
    let s = unsafe { CStr::from_ptr(p) };
    Some(s.to_string_lossy().into_owned())
}

pub fn load_from_env() -> Result<LoadedSnapshot, LoadError> {
    let manifest_env = unsafe { getenv_libc(c"SENTINEL_SNAPSHOT_MANIFEST") }
        .ok_or(LoadError::EnvUnset)?;
    let manifest_path = PathBuf::from(&manifest_env);
    let canonical = manifest_path.canonicalize().map_err(LoadError::Io)?;
    let state_dir = well_known_state_dir()
        .canonicalize()
        .map_err(LoadError::Io)?;
    if !canonical.starts_with(&state_dir) {
        return Err(LoadError::PathOutsideStateDir {
            canonical: canonical.display().to_string(),
            state_dir: state_dir.display().to_string(),
        });
    }

    // Open manifest with O_NOFOLLOW.
    let mut manifest_text = String::new();
    {
        let mut f = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&canonical)
            .map_err(|e| LoadError::OpenFailed(format!("manifest: {e}")))?;
        f.read_to_string(&mut manifest_text).map_err(LoadError::Io)?;
    }
    let mut lines = manifest_text.lines();
    let snapshot_path_str = lines.next().ok_or(LoadError::ManifestParseFailed)?;
    let digest_line = lines.next().ok_or(LoadError::ManifestParseFailed)?;
    let manifest_digest = digest_line
        .strip_prefix("digest=")
        .ok_or(LoadError::ManifestParseFailed)?;
    if manifest_digest.len() != 64 || !manifest_digest.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(LoadError::ManifestParseFailed);
    }

    // Validate snapshot path also under state_dir.
    let snapshot_path = Path::new(snapshot_path_str)
        .canonicalize()
        .map_err(LoadError::Io)?;
    if !snapshot_path.starts_with(&state_dir) {
        return Err(LoadError::PathOutsideStateDir {
            canonical: snapshot_path.display().to_string(),
            state_dir: state_dir.display().to_string(),
        });
    }

    // Open snapshot with O_NOFOLLOW; verify it is a regular file.
    let snap_file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&snapshot_path)
        .map_err(|e| LoadError::OpenFailed(format!("snapshot: {e}")))?;
    let meta = snap_file.metadata().map_err(LoadError::Io)?;
    if !meta.is_file() {
        return Err(LoadError::NotRegularFile(
            snapshot_path.display().to_string(),
        ));
    }

    // Read bytes, verify digest.
    let bytes = std::fs::read(&snapshot_path).map_err(LoadError::Io)?;
    let computed = format!("{:x}", Sha256::digest(&bytes));
    if computed != manifest_digest {
        return Err(LoadError::DigestMismatch {
            expected: manifest_digest.into(),
            got: computed,
        });
    }

    // Decode CBOR; verify schema.
    let snap = sentinel_core::Snapshot::decode(&bytes).map_err(|e| match e {
        sentinel_core::Error::SchemaVersionMismatch { expected, got } => {
            LoadError::SchemaMismatch { expected, got }
        }
        other => LoadError::Codec(other.to_string()),
    })?;

    // mmap is for the contract — Phase 1 actually uses the decoded Vec for matching,
    // but we keep the mmap alive so future phases (Phase 2 zero-copy) inherit a
    // working mmap path.
    let mmap = unsafe { Mmap::map(&snap_file).map_err(LoadError::Io)? };

    Ok(LoadedSnapshot {
        _mmap: mmap,
        entries: snap.entries,
        schema_version: snap.schema_version,
        snapshot_path,
    })
}
