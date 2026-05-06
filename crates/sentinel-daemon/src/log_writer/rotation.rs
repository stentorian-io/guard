//! crates/sentinel-daemon/src/log_writer/rotation.rs
//!
//! Phase 3 plan 03-05 — size-based rotation with detached gzip + retention pruning.

use std::fs;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

pub const SIZE_THRESHOLD: u64 = 16 * 1024 * 1024;     // 16 MiB
pub const MAX_ARCHIVES: usize = 7;
pub const MAX_TOTAL_BYTES: u64 = 256 * 1024 * 1024;   // 256 MiB
const ROTATED_GLOB_PREFIX: &str = "sentinel-";
const ROTATED_GLOB_SUFFIX_GZ: &str = ".log.gz";

pub fn should_rotate(active_path: &Path) -> bool {
    fs::metadata(active_path).map(|m| m.len() >= SIZE_THRESHOLD).unwrap_or(false)
}

pub fn rotate(active_path: &Path) -> io::Result<()> {
    let parent = active_path.parent().ok_or_else(|| io::Error::other("active log has no parent"))?;
    let stamp = chrono::Utc::now().format("%Y%m%d").to_string();
    let seq = next_sequence(parent, &stamp)?;
    let rotated = parent.join(format!("{ROTATED_GLOB_PREFIX}{stamp}-{seq:03}.log"));
    if active_path.exists() {
        fs::rename(active_path, &rotated)?;     // atomic on same fs
    }
    // Pitfall 5 / R-07: gzip in detached thread.
    let parent_owned = parent.to_path_buf();
    std::thread::Builder::new()
        .name("sentineld-log-rotate".into())
        .spawn(move || {
            if let Err(e) = gzip_in_place(&rotated) {
                tracing::warn!(error = %e, "log rotate gzip failed");
            }
            if let Err(e) = enforce_retention(&parent_owned) {
                tracing::warn!(error = %e, "log retention enforce failed");
            }
        })
        .ok();
    Ok(())
}

fn next_sequence(parent: &Path, stamp: &str) -> io::Result<u32> {
    let mut max = 0u32;
    let prefix = format!("{ROTATED_GLOB_PREFIX}{stamp}-");
    if let Ok(entries) = fs::read_dir(parent) {
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            if !name.starts_with(&prefix) { continue; }
            // Strip prefix; expect "NNN.log" or "NNN.log.gz".
            let rest = &name[prefix.len()..];
            let n_str = rest.split('.').next().unwrap_or("");
            if let Ok(n) = n_str.parse::<u32>() {
                if n > max { max = n; }
            }
        }
    }
    Ok(max + 1)
}

fn gzip_in_place(rotated: &Path) -> io::Result<()> {
    use flate2::write::GzEncoder;
    use flate2::Compression;
    let gz_path: PathBuf = {
        let mut s = rotated.as_os_str().to_owned();
        s.push(".gz");
        PathBuf::from(s)
    };
    {
        let mut input = fs::File::open(rotated)?;
        let output = fs::OpenOptions::new().write(true).create_new(true).open(&gz_path)?;
        let mut encoder = GzEncoder::new(output, Compression::default());
        let mut buf = [0u8; 64 * 1024];
        loop {
            let n = input.read(&mut buf)?;
            if n == 0 { break; }
            encoder.write_all(&buf[..n])?;
        }
        encoder.finish()?;
    }
    fs::remove_file(rotated)?;
    Ok(())
}

pub fn enforce_retention(dir: &Path) -> io::Result<()> {
    let mut archives: Vec<(PathBuf, std::time::SystemTime, u64)> = Vec::new();
    if let Ok(entries) = fs::read_dir(dir) {
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            if !name.starts_with(ROTATED_GLOB_PREFIX) || !name.ends_with(ROTATED_GLOB_SUFFIX_GZ) { continue; }
            let path = entry.path();
            let meta = fs::metadata(&path)?;
            let mtime = meta.modified().unwrap_or(std::time::SystemTime::UNIX_EPOCH);
            archives.push((path, mtime, meta.len()));
        }
    }
    // Oldest first.
    archives.sort_by_key(|(_, t, _)| *t);
    // (1) count cap
    while archives.len() > MAX_ARCHIVES {
        if let Some((p, _, _)) = archives.first() {
            let _ = fs::remove_file(p);
        }
        archives.remove(0);
    }
    // (2) total-size cap
    let mut total: u64 = archives.iter().map(|(_, _, s)| *s).sum();
    while total > MAX_TOTAL_BYTES && !archives.is_empty() {
        let (p, _, sz) = archives.remove(0);
        let _ = fs::remove_file(&p);
        total = total.saturating_sub(sz);
    }
    Ok(())
}
