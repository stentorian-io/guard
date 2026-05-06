//! crates/sentinel-cli/src/logs_follow.rs
//!
//! Phase 3 plan 03-10 — file-tail with rotation rename-detection (D-51).
//! Uses notify 8.2; A2 verified by plan 03-01 spike.
//! Pitfall 2: single non-recursive watch (RecursiveMode::NonRecursive).

use std::io::{Read, Seek, SeekFrom, Write};
use std::path::Path;
use std::sync::mpsc::channel;
use std::time::Duration;

use notify::{event::ModifyKind, recommended_watcher, EventKind, RecursiveMode, Watcher};

use crate::CliError;

pub fn tail(active_log: &Path) -> Result<(), CliError> {
    if let Some(parent) = active_log.parent() {
        std::fs::create_dir_all(parent).ok();
    }
    if !active_log.exists() {
        // touch so the watcher has something to subscribe to
        std::fs::File::create(active_log)
            .map_err(|e| CliError::Other(format!("touch active: {e}")))?;
    }

    let (tx, rx) = channel::<notify::Result<notify::Event>>();
    let mut watcher =
        recommended_watcher(tx).map_err(|e| CliError::Other(format!("notify: {e}")))?;
    watcher
        .watch(active_log, RecursiveMode::NonRecursive)
        .map_err(|e| CliError::Other(format!("notify watch: {e}")))?;

    let mut file = std::fs::File::open(active_log)
        .map_err(|e| CliError::Other(format!("open: {e}")))?;
    file.seek(SeekFrom::End(0)).ok();

    loop {
        // 1. drain any new bytes
        let mut buf = Vec::with_capacity(8 * 1024);
        let mut tmp = [0u8; 8 * 1024];
        loop {
            match file.read(&mut tmp) {
                Ok(0) => break,
                Ok(n) => buf.extend_from_slice(&tmp[..n]),
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(_) => break,
            }
        }
        if !buf.is_empty() {
            let stdout = std::io::stdout();
            let mut out = stdout.lock();
            let _ = out.write_all(&buf);
            let _ = out.flush();
        }

        // 2. block on notify event with a 1s safety-timeout (fallback for missed FSEvents)
        match rx.recv_timeout(Duration::from_secs(1)) {
            Ok(Ok(event)) => {
                if matches!(event.kind, EventKind::Modify(ModifyKind::Name(_))) {
                    // Rotation rename detected — reopen the new active file.
                    std::thread::sleep(Duration::from_millis(50));
                    if let Ok(f) = std::fs::File::open(active_log) {
                        file = f;
                        file.seek(SeekFrom::Start(0)).ok();
                    }
                }
                // For other events (Modify(Data), Create, etc.) we just loop and drain.
            }
            Ok(Err(e)) => {
                tracing::warn!(error = %e, "notify event error");
            }
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                // Periodic stat-fallback poll (R-02 mitigation): if file inode changed and
                // we missed the rename event, reopen.
                // This is a deliberately defensive belt-and-suspenders for FSEvents jitter.
                if let Ok(metadata_now) = std::fs::metadata(active_log) {
                    if let Ok(open_meta) = file.metadata() {
                        if metadata_now.len() < open_meta.len() {
                            // active file is now smaller than our open handle's view — likely truncated/recreated
                            if let Ok(f) = std::fs::File::open(active_log) {
                                file = f;
                                file.seek(SeekFrom::Start(0)).ok();
                            }
                        }
                    }
                }
            }
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => break,
        }
    }
    Ok(())
}
