//! Snapshot loader: read manifest from env, verify path under state_dir,
//! verify SHA-256 digest, mmap, parse schema_version.
//!
//! On ANY error: fail-closed (returns Err; lib.rs sets FAIL_CLOSED = true).

use core::sync::atomic::AtomicBool;
use hmac::{Hmac, Mac};
use memmap2::Mmap;
use sha2::{Digest, Sha256};
use std::ffi::CStr;
use std::fs::OpenOptions;
use std::io::Read;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

type HmacSha256 = Hmac<Sha256>;

pub static FAIL_CLOSED: AtomicBool = AtomicBool::new(false);

#[derive(Debug)]
pub enum LoadError {
    EnvUnset,
    PathOutsideStateDir { canonical: String, state_dir: String },
    OpenFailed(String),
    NotRegularFile(String),
    ManifestParseFailed,
    DigestMismatch { expected: String, got: String },
    HmacMissing,
    HmacMismatch,
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
///
/// ISS-07/ISS-12 remediation: honor SENTINEL_STATE_DIR env var override if set.
/// This lets the e2e test harness use a short /tmp-based state dir (required to
/// keep the Unix socket path under macOS's 104-byte SUN_LEN limit) while the
/// dylib still validates the manifest path correctly. When SENTINEL_STATE_DIR is
/// not set, fall back to HOME-derivation (the production default).
pub fn well_known_state_dir() -> PathBuf {
    // Check SENTINEL_STATE_DIR override first (using libc getenv to stay
    // allocation-free on the ctor path).
    let override_val = unsafe { getenv_libc(c"SENTINEL_STATE_DIR") };
    if let Some(s) = override_val {
        if !s.is_empty() {
            return PathBuf::from(s);
        }
    }
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
    let manifest_hmac = lines.next().and_then(|line| {
        let h = line.strip_prefix("hmac=")?;
        if h.len() == 64 && h.chars().all(|c| c.is_ascii_hexdigit()) {
            Some(h.to_string())
        } else {
            None
        }
    });

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
    //
    // BL-01 fix: use a SINGLE fd for both digest computation and mmap.
    // Previously std::fs::read(&snapshot_path) re-opened by path, creating
    // a TOCTOU window between the path-based open and the mmap. Now we open
    // once, read all bytes via the same fd for digest, then Mmap::map using
    // the SAME fd — the kernel guarantees both digest input and mapped bytes
    // come from the same inode instance.
    let mut snap_file = OpenOptions::new()
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

    // Read bytes via the existing fd (NOT std::fs::read which re-opens by path).
    // The file cursor is consumed; we seek back to the start before mmap.
    let mut bytes = Vec::with_capacity(meta.len() as usize);
    snap_file.read_to_end(&mut bytes).map_err(LoadError::Io)?;
    let computed = format!("{:x}", Sha256::digest(&bytes));
    if computed != manifest_digest {
        return Err(LoadError::DigestMismatch {
            expected: manifest_digest.into(),
            got: computed,
        });
    }

    // HMAC verification (M004-S02): if the key exists, the manifest MUST
    // contain a valid HMAC. This prevents an attacker from replacing both
    // the snapshot and manifest without knowing the key.
    if let Some(hmac_key) = load_hmac_key(&state_dir) {
        let expected_hmac = manifest_hmac.ok_or(LoadError::HmacMissing)?;
        let mut mac = HmacSha256::new_from_slice(&hmac_key).expect("key length valid");
        mac.update(&bytes);
        let computed_hmac = hex_lower(&mac.finalize().into_bytes());
        if computed_hmac != expected_hmac {
            return Err(LoadError::HmacMismatch);
        }
    }

    // Decode CBOR; verify schema.
    let snap = sentinel_core::Snapshot::decode(&bytes).map_err(|e| match e {
        sentinel_core::Error::SchemaVersionMismatch { expected, got } => {
            LoadError::SchemaMismatch { expected, got }
        }
        other => LoadError::Codec(other.to_string()),
    })?;

    // mmap from the SAME fd. Mmap::map operates on the file descriptor
    // independent of the file position (position was consumed by read_to_end
    // but mmap works at the inode level, not the cursor).
    //
    // Phase 1: mmap kept alive so future phases (Phase 2 zero-copy) inherit a
    // working mmap path. The decoded Vec is used for matching.
    let mmap = unsafe { Mmap::map(&snap_file).map_err(LoadError::Io)? };

    Ok(LoadedSnapshot {
        _mmap: mmap,
        entries: snap.entries,
        schema_version: snap.schema_version,
        snapshot_path,
    })
}

const HMAC_KEY_LEN: usize = 32;

fn load_hmac_key(state_dir: &Path) -> Option<[u8; HMAC_KEY_LEN]> {
    let path = state_dir.join("hmac.key");
    let mut f = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&path)
        .ok()?;
    let mut buf = [0u8; HMAC_KEY_LEN];
    let n = f.read(&mut buf).ok()?;
    if n != HMAC_KEY_LEN {
        return None;
    }
    let mut extra = [0u8; 1];
    if f.read(&mut extra).ok() != Some(0) {
        return None;
    }
    Some(buf)
}

fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 0xf) as usize] as char);
    }
    s
}
