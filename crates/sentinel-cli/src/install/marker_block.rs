//! crates/sentinel-cli/src/install/marker_block.rs
//!
//! Phase 3 plan 03-09 — atomic dotfile marker block (D-66, D-67) with R-04
//! symlink-follow + Pitfall 1 mitigation.

use std::io::Write;
use std::path::{Path, PathBuf};

pub const BEGIN_MARKER: &str = "# >>> sentinel >>>";
pub const END_MARKER: &str = "# <<< sentinel <<<";
pub const STUB_BODY: &str = "# managed by `sentinel install` — do not edit between markers\n[ -f \"$HOME/.config/sentinel/init.sh\" ] && . \"$HOME/.config/sentinel/init.sh\"\n";

pub fn canonical_block() -> String {
    format!("{BEGIN_MARKER}\n{STUB_BODY}{END_MARKER}\n")
}

pub fn canonical_block_sha256() -> String {
    use sha2::{Digest, Sha256};
    format!("{:x}", Sha256::digest(canonical_block().as_bytes()))
}

/// Detect rc files present under HOME (D-67).
pub fn detect_rc_files() -> Vec<PathBuf> {
    let home = super::launchagent::home_dir();
    let candidates = [
        home.join(".zshrc"),
        home.join(".bashrc"),
        home.join(".bash_profile"),
        home.join(".config").join("fish").join("config.fish"),
    ];
    candidates.into_iter().filter(|p| p.exists()).collect()
}

/// CR-03: capture the existing file's mode (and uid/gid as best-effort) before
/// `tf.persist` clobbers them. `tempfile::NamedTempFile` creates with mode
/// 0600 and the current uid/gid; `persist` calls rename(2) which replaces the
/// target inode, dropping the original mode/owner/group. We re-apply the
/// captured permissions afterwards so a user's `.zshrc` (typically 0644)
/// stays 0644 instead of silently becoming 0600.
fn capture_metadata(target: &Path) -> Option<std::fs::Metadata> {
    std::fs::metadata(target).ok()
}

fn restore_metadata(target: &Path, meta: Option<&std::fs::Metadata>) {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    let Some(meta) = meta else { return };
    // Restore mode bits.
    let mode = meta.permissions().mode();
    let _ = std::fs::set_permissions(target, std::fs::Permissions::from_mode(mode));
    // Best-effort uid/gid restore. Sentinel runs as the user with no privilege
    // boundary so the typical case is a no-op (uid/gid already match), but if
    // the rc file was originally owned by a different uid we'd otherwise leave
    // it owned by the CLI's current uid after persist.
    let uid = meta.uid();
    let gid = meta.gid();
    let cstr = match std::ffi::CString::new(target.as_os_str().as_encoded_bytes()) {
        Ok(c) => c,
        Err(_) => return,
    };
    // SAFETY: CString outlives the call; chown returns -1 on failure which we ignore.
    unsafe {
        let _ = libc::chown(cstr.as_ptr(), uid, gid);
    }
}

/// Install (or replace) the marker block. Returns the canonical path actually
/// written (the symlink target if rc_path is a symlink — R-04 mitigation).
pub fn install(rc_path: &Path) -> std::io::Result<PathBuf> {
    let target = std::fs::canonicalize(rc_path).unwrap_or_else(|_| rc_path.to_path_buf());
    // CR-03: snapshot the current rc file's mode/owner BEFORE we rename our
    // tempfile over it. None when the rc file does not yet exist (first install).
    let original_meta = capture_metadata(&target);
    let original = std::fs::read_to_string(&target).unwrap_or_default();
    let new = upsert_block(&original);
    let parent = target.parent().ok_or_else(|| std::io::Error::other("rc has no parent"))?;
    let mut tf = tempfile::NamedTempFile::new_in(parent)?;
    tf.write_all(new.as_bytes())?;
    tf.as_file().sync_all()?;
    tf.persist(&target).map_err(|e| std::io::Error::other(format!("persist: {e}")))?;
    // CR-03: re-apply the original mode/owner so a 0644 .zshrc stays 0644.
    restore_metadata(&target, original_meta.as_ref());
    Ok(target)
}

/// Strip marker block (idempotent — no-op if absent).
///
/// WR-03: handle dangling-symlink and missing-file cases explicitly. The prior
/// `unwrap_or_else(|_| rc_path.to_path_buf())` fallback returned a relative
/// path on canonicalize failure, which then caused
/// `tempfile::NamedTempFile::new_in(parent)` to create the temp file in the
/// daemon's cwd; the subsequent `persist` could cross filesystems and fail
/// with EXDEV, leaving stale state. We now treat a missing target as a benign
/// no-op and propagate any other canonicalize error to the caller.
pub fn strip(rc_path: &Path) -> std::io::Result<()> {
    let target = match std::fs::canonicalize(rc_path) {
        Ok(p) => p,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => {
            return Err(std::io::Error::other(format!(
                "canonicalize {}: {e}",
                rc_path.display()
            )));
        }
    };
    let original = match std::fs::read_to_string(&target) {
        Ok(s) => s,
        Err(_) => return Ok(()),    // file gone — already removed
    };
    let stripped = remove_block(&original);
    if stripped == original { return Ok(()); }
    let parent = target.parent().ok_or_else(|| std::io::Error::other("rc has no parent"))?;
    // CR-03: capture metadata before persist; re-apply after.
    let original_meta = capture_metadata(&target);
    let mut tf = tempfile::NamedTempFile::new_in(parent)?;
    tf.write_all(stripped.as_bytes())?;
    tf.as_file().sync_all()?;
    tf.persist(&target).map_err(|e| std::io::Error::other(format!("persist: {e}")))?;
    restore_metadata(&target, original_meta.as_ref());
    Ok(())
}

fn upsert_block(existing: &str) -> String {
    if let (Some(b), Some(e)) = (existing.find(BEGIN_MARKER), existing.find(END_MARKER)) {
        let after_end = e + END_MARKER.len();
        let trailing_nl = if existing[after_end..].starts_with('\n') { 1 } else { 0 };
        let mut out = String::with_capacity(existing.len());
        out.push_str(&existing[..b]);
        out.push_str(&canonical_block());
        out.push_str(&existing[after_end + trailing_nl..]);
        out
    } else {
        let mut out = existing.to_string();
        if !out.ends_with('\n') && !out.is_empty() { out.push('\n'); }
        if !out.is_empty() { out.push('\n'); }
        out.push_str(&canonical_block());
        out
    }
}

fn remove_block(existing: &str) -> String {
    if let (Some(b), Some(e)) = (existing.find(BEGIN_MARKER), existing.find(END_MARKER)) {
        let after_end = e + END_MARKER.len();
        let trailing_nl = if existing[after_end..].starts_with('\n') { 1 } else { 0 };
        // Also strip a leading blank line that we added during upsert (defensive).
        let mut prefix_end = b;
        let prefix_bytes = existing[..b].as_bytes();
        if prefix_bytes.last().copied() == Some(b'\n') && prefix_end >= 2 && prefix_bytes[prefix_bytes.len()-2] == b'\n' {
            prefix_end -= 1;
        }
        let mut out = String::with_capacity(existing.len());
        out.push_str(&existing[..prefix_end]);
        out.push_str(&existing[after_end + trailing_nl..]);
        out
    } else {
        existing.to_string()
    }
}
