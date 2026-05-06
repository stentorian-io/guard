//! crates/sentinel-daemon/src/log_writer/mod.rs
//!
//! Phase 3 — forensic JSONL log writer (D-49, D-50).
//!
//! - Bounded mpsc input (`crossbeam_channel::bounded(4096)`) — drop-tolerant on full queue
//! - Dedicated writer thread named `sentineld-log-writer`
//! - Size-rotation at SIZE_THRESHOLD with atomic rename + detached gzip (Pitfall 5)
//! - Retention pruning enforced after each rotation (D-50: 7 archives + 256 MiB cap)
//! - Atomic counters expose blocks_today / allows_today / gaps_today for StatusReply

pub mod jsonl_row;
pub mod rotation;
pub mod package_context;

pub use jsonl_row::{LogRow, Decision, GapRecord, ProcessCtxLog, RootCtxLog,
                    JSONL_SCHEMA_VERSION, truncate_argv, now_rfc3339};
pub use package_context::infer_package_context;

use std::fs::{File, OpenOptions};
use std::io;
use std::os::unix::fs::OpenOptionsExt;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use crossbeam_channel::{bounded, Sender, TrySendError};

const QUEUE_CAPACITY: usize = 4096;

#[derive(Clone)]
pub struct LogWriter {
    tx: Sender<LogRow>,
    pub blocks_today: Arc<AtomicU64>,
    pub allows_today: Arc<AtomicU64>,
    pub gaps_today: Arc<AtomicU64>,
}

impl LogWriter {
    /// Spawn the dedicated writer thread.
    /// Caller passes the active log path (e.g. `~/Library/Logs/Sentinel/sentinel.log`).
    pub fn spawn(log_path: PathBuf) -> io::Result<Self> {
        if let Some(parent) = log_path.parent() {
            std::fs::create_dir_all(parent)?;
            // Best-effort 0700 on the dir.
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(
                parent,
                std::fs::Permissions::from_mode(0o700),
            );
        }
        let initial_file = open_active(&log_path)?;
        let (tx, rx) = bounded::<LogRow>(QUEUE_CAPACITY);
        let blocks = Arc::new(AtomicU64::new(0));
        let allows = Arc::new(AtomicU64::new(0));
        let gaps = Arc::new(AtomicU64::new(0));
        let blocks_t = Arc::clone(&blocks);
        let allows_t = Arc::clone(&allows);
        let gaps_t = Arc::clone(&gaps);
        std::thread::Builder::new()
            .name("sentineld-log-writer".into())
            .spawn(move || {
                let mut active = initial_file;
                while let Ok(row) = rx.recv() {
                    match &row {
                        LogRow::Block(_) => { blocks_t.fetch_add(1, Ordering::Relaxed); }
                        LogRow::Allow(_) => { allows_t.fetch_add(1, Ordering::Relaxed); }
                        LogRow::Gap(_)   => { gaps_t.fetch_add(1, Ordering::Relaxed); }
                    }
                    if let Err(e) = jsonl_row::append(&mut active, &row) {
                        tracing::warn!(error = %e, "log write failed");
                    }
                    if rotation::should_rotate(&log_path) {
                        if let Err(e) = rotation::rotate(&log_path) {
                            tracing::warn!(error = %e, "log rotate failed");
                        }
                        match open_active(&log_path) {
                            Ok(f) => active = f,
                            Err(e) => { tracing::error!(error = %e, "reopen post-rotate failed"); break; }
                        }
                    }
                }
            })?;
        Ok(Self { tx, blocks_today: blocks, allows_today: allows, gaps_today: gaps })
    }

    /// Try to enqueue a row. Drops on a full queue (defense against unbounded growth).
    pub fn send(&self, row: LogRow) {
        match self.tx.try_send(row) {
            Ok(()) => {}
            Err(TrySendError::Full(_)) => {
                tracing::warn!("log_writer queue full; dropping row");
            }
            Err(TrySendError::Disconnected(_)) => {
                tracing::error!("log_writer thread disconnected");
            }
        }
    }

    pub fn counters_snapshot(&self) -> (u64, u64, u64) {
        (
            self.blocks_today.load(Ordering::Relaxed),
            self.allows_today.load(Ordering::Relaxed),
            self.gaps_today.load(Ordering::Relaxed),
        )
    }
}

fn open_active(path: &std::path::Path) -> io::Result<File> {
    OpenOptions::new()
        .create(true)
        .append(true)
        .mode(0o600)
        .open(path)
}
