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
    // CR-06: use a millisecond-precision timestamp + per-process counter to
    // make collisions effectively impossible. The previous scheme scanned the
    // directory for the highest existing seq number; that scan races with the
    // detached gzip thread (which removes the .log and creates the .log.gz),
    // so two near-simultaneous rotations could both compute the same seq and
    // the second `fs::rename` would silently clobber the first rotation's
    // data. ms-precision + an atomic in-process counter guarantees a unique
    // rotated filename for every call to rotate().
    let stamp = chrono::Utc::now().format("%Y%m%dT%H%M%S%3f").to_string();
    let seq = next_in_process_seq();
    let rotated = parent.join(format!("{ROTATED_GLOB_PREFIX}{stamp}-{seq:03}.log"));
    if active_path.exists() {
        // Best-effort guard: if the rotated path already exists (extremely
        // unlikely with ms precision, but possible if the system clock was
        // rolled back), bump seq until we find an open slot. Caps at a small
        // bound; beyond that we fall through and let `rename` clobber, which
        // is at worst the prior bug's behavior.
        let mut final_rotated = rotated.clone();
        let mut bump = 0u32;
        while final_rotated.exists() && bump < 64 {
            bump += 1;
            let alt_seq = seq + bump;
            final_rotated = parent.join(format!(
                "{ROTATED_GLOB_PREFIX}{stamp}-{alt_seq:03}.log"
            ));
        }
        fs::rename(active_path, &final_rotated)?; // atomic on same fs
        let rotated = final_rotated;
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
    }
    Ok(())
}

/// CR-06: per-process monotonic counter. Combined with millisecond-precision
/// timestamps, makes `(stamp, seq)` unique even under heavy rotation contention
/// from concurrent threads in the same daemon process.
fn next_in_process_seq() -> u32 {
    use std::sync::atomic::{AtomicU32, Ordering};
    static COUNTER: AtomicU32 = AtomicU32::new(0);
    COUNTER.fetch_add(1, Ordering::Relaxed) % 1000
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
