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
    /// Create a no-op LogWriter whose channel is immediately disconnected.
    /// Used by DaemonState::new (the Phase 2 compat constructor) and in tests
    /// where a live writer thread is undesirable.
    pub fn noop() -> Self {
        let (tx, _rx) = bounded::<LogRow>(1);
        // Drop _rx immediately — the sender will see Disconnected on any send,
        // which `send()` already handles gracefully (tracing::error log only).
        Self {
            tx,
            blocks_today: Arc::new(AtomicU64::new(0)),
            allows_today: Arc::new(AtomicU64::new(0)),
            gaps_today: Arc::new(AtomicU64::new(0)),
        }
    }

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
        // WR-05: bound dest_host length on the way in. A hostile package
        // calling connect() with an attacker-controlled multi-KiB hostname
        // would otherwise produce log lines of arbitrary size (the active log
        // is bounded by 16 MiB rotation but downstream consumers like
        // `sentinel approve --from-log` accumulate entries in memory).
        let row = clamp_row(row);
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

/// WR-05: maximum length for a `dest_host` field in a log row. RFC1035 caps DNS
/// names at 255 octets; we round up to 256 as the on-disk cap. Anything longer
/// is attacker-controlled garbage and gets truncated.
const MAX_DEST_HOST_LEN: usize = 256;

/// WR-05: truncate any oversized fields in a LogRow before enqueuing. Keeps
/// individual JSONL entries bounded so a hostile package emitting multi-KiB
/// hostnames cannot blow up downstream consumers (e.g. `sentinel approve
/// --from-log`).
fn clamp_row(row: LogRow) -> LogRow {
    match row {
        LogRow::Block(mut d) => {
            clamp_decision(&mut d);
            LogRow::Block(d)
        }
        LogRow::Allow(mut d) => {
            clamp_decision(&mut d);
            LogRow::Allow(d)
        }
        // Gap rows have no dest_host field.
        other => other,
    }
}

fn clamp_decision(d: &mut Decision) {
    if d.dest_host.len() > MAX_DEST_HOST_LEN {
        let mut end = MAX_DEST_HOST_LEN;
        while end > 0 && !d.dest_host.is_char_boundary(end) {
            end -= 1;
        }
        d.dest_host.truncate(end);
    }
}
