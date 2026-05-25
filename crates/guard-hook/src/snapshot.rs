//! Snapshot loader: read manifest from env, verify path under state_dir,
//! verify SHA-256 digest and snapshot signature, mmap, parse schema_version.
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
    PathOutsideStateDir {
        canonical: String,
        state_dir: String,
    },
    OpenFailed(String),
    NotRegularFile(String),
    ManifestParseFailed,
    DigestMismatch {
        expected: String,
        got: String,
    },
    SchemaMismatch {
        expected: u16,
        got: u16,
    },
    Io(std::io::Error),
    Codec(String),
    SnapshotSignatureMissing,
    SnapshotSignatureMismatch(String),
    SnapshotSignerUntrusted,
    TrustedSignerManifestInvalid(String),
}

struct ManifestSnapshotSignature {
    scheme: String,
    signer_kind: String,
    public_key_sha256: String,
    public_key_x963: Vec<u8>,
    signature_der: Vec<u8>,
    signed_payload_sha256: String,
    signature_created_at_unix_ms: i64,
}

pub struct LoadedSnapshot {
    pub _mmap: Mmap, // borrowed by entries; keep alive
    pub entries: Vec<guard_core::AllowlistEntry>,
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

/// v0.1 well-known state_dir for path validation.
///
/// ISS-07/ISS-12 remediation: honor STT_GUARD_STATE_DIR env var override if set.
/// This lets the e2e test harness use a short /tmp-based state dir (required to
/// keep the Unix socket path under macOS's 104-byte SUN_LEN limit) while the
/// dylib still validates the manifest path correctly. When STT_GUARD_STATE_DIR is
/// not set, fall back to HOME-derivation (the production default).
pub fn well_known_state_dir() -> PathBuf {
    // Check STT_GUARD_STATE_DIR override first (using libc getenv to stay
    // allocation-free on the ctor path).
    let override_val = unsafe {
        getenv_libc(CStr::from_bytes_with_nul_unchecked(
            b"STT_GUARD_STATE_DIR\0",
        ))
    };
    if let Some(s) = override_val {
        if !s.is_empty() {
            return PathBuf::from(s);
        }
    }
    let home = std::env::var_os("HOME").expect("HOME environment variable must be set");
    PathBuf::from(home).join(format!(
        "Library/Application Support/{}",
        guard_core::paths::APP_NAME,
    ))
}

/// Read STT_GUARD_SNAPSHOT_MANIFEST via libc::getenv to avoid std::env::var
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
    let manifest_env = unsafe {
        getenv_libc(CStr::from_bytes_with_nul_unchecked(
            b"STT_GUARD_SNAPSHOT_MANIFEST\0",
        ))
    }
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
        f.read_to_string(&mut manifest_text)
            .map_err(LoadError::Io)?;
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
    let mut signature_scheme: Option<String> = None;
    let mut signer_kind: Option<String> = None;
    let mut public_key_sha256: Option<String> = None;
    let mut public_key_x963: Option<Vec<u8>> = None;
    let mut signature_der: Option<Vec<u8>> = None;
    let mut signed_payload_sha256: Option<String> = None;
    let mut signature_created_at_unix_ms: Option<i64> = None;
    for line in lines {
        if let Some(value) = line.strip_prefix("snapshot_signature_scheme=") {
            signature_scheme = Some(value.to_string());
        } else if let Some(value) = line.strip_prefix("snapshot_signer_kind=") {
            signer_kind = Some(value.to_string());
        } else if let Some(value) = line.strip_prefix("snapshot_public_key_sha256=") {
            public_key_sha256 = Some(value.to_string());
        } else if let Some(value) = line.strip_prefix("snapshot_public_key_x963=") {
            public_key_x963 = Some(decode_hex(value).map_err(|_| LoadError::ManifestParseFailed)?);
        } else if let Some(value) = line.strip_prefix("snapshot_signature_der=") {
            signature_der = Some(decode_hex(value).map_err(|_| LoadError::ManifestParseFailed)?);
        } else if let Some(value) = line.strip_prefix("snapshot_signed_payload_sha256=") {
            signed_payload_sha256 = Some(value.to_string());
        } else if let Some(value) = line.strip_prefix("snapshot_signature_created_at_unix_ms=") {
            signature_created_at_unix_ms = Some(
                value
                    .parse::<i64>()
                    .map_err(|_| LoadError::ManifestParseFailed)?,
            );
        }
    }
    let manifest_signature = ManifestSnapshotSignature {
        scheme: signature_scheme.ok_or(LoadError::SnapshotSignatureMissing)?,
        signer_kind: signer_kind.ok_or(LoadError::SnapshotSignatureMissing)?,
        public_key_sha256: public_key_sha256.ok_or(LoadError::SnapshotSignatureMissing)?,
        public_key_x963: public_key_x963.ok_or(LoadError::SnapshotSignatureMissing)?,
        signature_der: signature_der.ok_or(LoadError::SnapshotSignatureMissing)?,
        signed_payload_sha256: signed_payload_sha256.ok_or(LoadError::SnapshotSignatureMissing)?,
        signature_created_at_unix_ms: signature_created_at_unix_ms
            .ok_or(LoadError::SnapshotSignatureMissing)?,
    };

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

    // Decode CBOR; verify schema.
    let snap = guard_core::Snapshot::decode(&bytes).map_err(|e| match e {
        guard_core::Error::SchemaVersionMismatch { expected, got } => {
            LoadError::SchemaMismatch { expected, got }
        }
        other => LoadError::Codec(other.to_string()),
    })?;

    verify_snapshot_signature(&snap, &computed, &manifest_signature, &state_dir)?;

    // mmap from the SAME fd. Mmap::map operates on the file descriptor
    // independent of the file position (position was consumed by read_to_end
    // but mmap works at the inode level, not the cursor).
    //
    // v0.1: mmap kept alive so future versions (v0.2 zero-copy) inherit a
    // working mmap path. The decoded Vec is used for matching.
    let mmap = unsafe { Mmap::map(&snap_file).map_err(LoadError::Io)? };

    Ok(LoadedSnapshot {
        _mmap: mmap,
        entries: snap.entries,
        schema_version: snap.schema_version,
        snapshot_path,
    })
}

fn verify_snapshot_signature(
    snapshot: &guard_core::Snapshot,
    snapshot_sha256: &str,
    manifest_signature: &ManifestSnapshotSignature,
    state_dir: &Path,
) -> Result<(), LoadError> {
    let run_uuid = snapshot
        .run_uuid
        .as_ref()
        .ok_or(LoadError::SnapshotSignatureMissing)?;
    let payload = guard_core::SnapshotSignaturePayloadV1::new(
        run_uuid.clone(),
        snapshot_sha256.to_string(),
        snapshot.generated_at_unix_ms,
    );
    let signature = guard_core::SnapshotSignatureV1 {
        scheme: manifest_signature.scheme.clone(),
        signer_kind: manifest_signature.signer_kind.clone(),
        public_key_x963: manifest_signature.public_key_x963.clone(),
        public_key_sha256: manifest_signature.public_key_sha256.clone(),
        signature_der: manifest_signature.signature_der.clone(),
        signed_payload_sha256: manifest_signature.signed_payload_sha256.clone(),
        signature_created_at_unix_ms: manifest_signature.signature_created_at_unix_ms,
    };
    guard_core::verify_snapshot_signature(&payload, &signature, snapshot_signature_policy())
        .map_err(|e| LoadError::SnapshotSignatureMismatch(e.to_string()))?;
    if !trusted_signer_manifest_contains(&signature, state_dir)? {
        return Err(LoadError::SnapshotSignerUntrusted);
    }
    Ok(())
}

fn snapshot_signature_policy() -> guard_core::RuleSignaturePolicy {
    if cfg!(feature = "test-signer") {
        guard_core::RuleSignaturePolicy::AllowTestSimulator
    } else {
        guard_core::RuleSignaturePolicy::Production
    }
}

fn trusted_signer_manifest_contains(
    signature: &guard_core::SnapshotSignatureV1,
    state_dir: &Path,
) -> Result<bool, LoadError> {
    let mut path = guard_core::paths::trusted_rule_signers_path();
    if (cfg!(debug_assertions) || cfg!(feature = "test-signer")) && !path.exists() {
        path = state_dir.join(guard_core::paths::TRUSTED_RULE_SIGNERS_FILENAME);
    }
    verify_trusted_signer_manifest_path(&path)?;
    let contents = std::fs::read_to_string(&path)
        .map_err(|e| LoadError::TrustedSignerManifestInvalid(e.to_string()))?;
    guard_core::trusted_signer_matches(
        &contents,
        &signature.public_key_sha256,
        &signature.signer_kind,
        Some(&signature.public_key_x963),
    )
    .map_err(|e| LoadError::TrustedSignerManifestInvalid(e.to_string()))
}

fn verify_trusted_signer_manifest_path(path: &Path) -> Result<(), LoadError> {
    let meta = std::fs::symlink_metadata(path)
        .map_err(|e| LoadError::TrustedSignerManifestInvalid(e.to_string()))?;
    if !meta.file_type().is_file() {
        return Err(LoadError::TrustedSignerManifestInvalid(
            "trusted signer manifest is not a regular file".to_string(),
        ));
    }
    #[cfg(all(not(debug_assertions), not(feature = "test-signer")))]
    {
        use std::os::unix::fs::MetadataExt;
        if meta.uid() != 0 || meta.gid() != 0 || meta.mode() & 0o022 != 0 {
            return Err(LoadError::TrustedSignerManifestInvalid(
                "trusted signer manifest has unsafe ownership or permissions".to_string(),
            ));
        }
        let parent = path.parent().ok_or_else(|| {
            LoadError::TrustedSignerManifestInvalid(
                "trusted signer manifest has no parent directory".to_string(),
            )
        })?;
        let parent_meta = std::fs::symlink_metadata(parent)
            .map_err(|e| LoadError::TrustedSignerManifestInvalid(e.to_string()))?;
        if !parent_meta.file_type().is_dir()
            || parent_meta.uid() != 0
            || parent_meta.gid() != 0
            || parent_meta.mode() & 0o022 != 0
        {
            return Err(LoadError::TrustedSignerManifestInvalid(
                "trusted signer manifest parent has unsafe ownership or permissions".to_string(),
            ));
        }
    }
    Ok(())
}

fn decode_hex(s: &str) -> Result<Vec<u8>, ()> {
    if s.len() % 2 != 0 {
        return Err(());
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    for pair in s.as_bytes().chunks_exact(2) {
        let hi = hex_value(pair[0])?;
        let lo = hex_value(pair[1])?;
        out.push((hi << 4) | lo);
    }
    Ok(out)
}

fn hex_value(b: u8) -> Result<u8, ()> {
    match b {
        b'0'..=b'9' => Ok(b - b'0'),
        b'a'..=b'f' => Ok(b - b'a' + 10),
        b'A'..=b'F' => Ok(b - b'A' + 10),
        _ => Err(()),
    }
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
