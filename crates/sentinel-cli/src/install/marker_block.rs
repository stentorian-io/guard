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

/// Install (or replace) the marker block. Returns the canonical path actually
/// written (the symlink target if rc_path is a symlink — R-04 mitigation).
pub fn install(rc_path: &Path) -> std::io::Result<PathBuf> {
    let target = std::fs::canonicalize(rc_path).unwrap_or_else(|_| rc_path.to_path_buf());
    let original = std::fs::read_to_string(&target).unwrap_or_default();
    let new = upsert_block(&original);
    let parent = target.parent().ok_or_else(|| std::io::Error::other("rc has no parent"))?;
    let mut tf = tempfile::NamedTempFile::new_in(parent)?;
    tf.write_all(new.as_bytes())?;
    tf.as_file().sync_all()?;
    tf.persist(&target).map_err(|e| std::io::Error::other(format!("persist: {e}")))?;
    Ok(target)
}

/// Strip marker block (idempotent — no-op if absent).
pub fn strip(rc_path: &Path) -> std::io::Result<()> {
    let target = std::fs::canonicalize(rc_path).unwrap_or_else(|_| rc_path.to_path_buf());
    let original = match std::fs::read_to_string(&target) {
        Ok(s) => s,
        Err(_) => return Ok(()),    // file gone — already removed
    };
    let stripped = remove_block(&original);
    if stripped == original { return Ok(()); }
    let parent = target.parent().ok_or_else(|| std::io::Error::other("rc has no parent"))?;
    let mut tf = tempfile::NamedTempFile::new_in(parent)?;
    tf.write_all(stripped.as_bytes())?;
    tf.as_file().sync_all()?;
    tf.persist(&target).map_err(|e| std::io::Error::other(format!("persist: {e}")))?;
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
