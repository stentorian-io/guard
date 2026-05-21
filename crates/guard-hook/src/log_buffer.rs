//! Concurrent-writer-safe log ring (BL-03 / D-43 fix).
//!
//! v0.1's SpscRing was a single-producer-single-consumer approximation
//! that accepted writes from multiple threads (replace_libc.rs hot paths) —
//! racy by design. v0.2 replaces it with `crossbeam_queue::ArrayQueue<Box<[u8]>>`,
//! a lock-free MPMC queue with proven correctness.
//!
//! The append API takes `&[u8]` (unchanged from v0.1) and copies into an
//! owned `Box<[u8]>` — this allocates, which would normally violate D-03's
//! no-alloc-on-the-hot-path rule, BUT the log ring is NOT on the verdict hot
//! path (the hot path is connect/sendto, which decides allow/deny without
//! touching LOG_RING). Fork/exec hooks DO call append, and they are not on
//! the <100µs budget — they pay an IPC round trip. A small-byte malloc is
//! fine in that context.
//!
//! On overflow: `force_push` evicts the oldest entry. The log is lossy by
//! design — we prefer recent records over a hung writer.

use crossbeam_queue::ArrayQueue;
use std::sync::OnceLock;

const CAPACITY: usize = 1024;

static LOG_RING_INNER: OnceLock<ArrayQueue<Box<[u8]>>> = OnceLock::new();

fn ring() -> &'static ArrayQueue<Box<[u8]>> {
    LOG_RING_INNER.get_or_init(|| ArrayQueue::new(CAPACITY))
}

/// Process-global log ring. v0.1 callers wrote `LOG_RING.append(...)`.
/// The static is a unit struct delegating to the OnceLock-backed inner queue;
/// this preserves the call-site syntax exactly while routing all writes
/// through the lock-free MPMC ArrayQueue.
pub struct LogRing;

pub static LOG_RING: LogRing = LogRing;

impl LogRing {
    /// Capacity of the ring (entries, not bytes). Lossy on overflow.
    pub const CAPACITY: usize = CAPACITY;

    /// Append a log line. Allocates a `Box<[u8]>` from `msg` plus a trailing
    /// newline. Lossy on overflow (oldest evicted via `force_push`). Safe
    /// under concurrent writers (lock-free MPMC).
    pub fn append(&self, msg: &[u8]) {
        let mut v = Vec::with_capacity(msg.len() + 1);
        v.extend_from_slice(msg);
        v.push(b'\n');
        let _ = ring().force_push(v.into_boxed_slice());
    }

    /// Drain the queue into `out`. Concatenates each entry's bytes; entries
    /// already include trailing newlines.
    pub fn dump(&self, out: &mut Vec<u8>) {
        while let Some(entry) = ring().pop() {
            out.extend_from_slice(&entry);
        }
    }

    /// Number of entries currently buffered. Useful for tests.
    pub fn len(&self) -> usize {
        ring().len()
    }

    /// True if the buffer is empty. Pairs with `len()` to satisfy
    /// clippy::len_without_is_empty.
    pub fn is_empty(&self) -> bool {
        ring().is_empty()
    }
}
