//! Fixed-capacity SPSC log ring for use from hot-path code (D-03 — no alloc).
//!
//! Phase 1 keeps it simple: a static byte buffer + atomic write index. The
//! constructor and a future flush thread read the buffer; replacement fns
//! append. Lossy: if the buffer fills, new writes overwrite from index 0.
//!
//! For Phase 1 this is dev-only (we read it via `dump()` in tests). Phase 3
//! wires the flush thread to write structured records to ~/Library/Logs/Sentinel.

use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicUsize, Ordering};

const RING_BYTES: usize = 64 * 1024;

pub struct SpscRing {
    // UnsafeCell so we can write through a shared reference from the static.
    buf: UnsafeCell<[u8; RING_BYTES]>,
    write_idx: AtomicUsize,
}

// SAFETY: SpscRing is accessed from multiple threads only via atomic
// write_idx (monotonic) + UnsafeCell buf (SPSC approximation). For Phase 1
// this is acceptable; Phase 3 replaces with a proper per-thread ring.
unsafe impl Sync for SpscRing {}

pub static LOG_RING: SpscRing = SpscRing {
    buf: UnsafeCell::new([0; RING_BYTES]),
    write_idx: AtomicUsize::new(0),
};

impl SpscRing {
    /// Append `msg` followed by a newline. Lossy on overflow.
    pub fn append(&self, msg: &[u8]) {
        // Reserve a slot; lossy wrap on overflow.
        let len = msg.len() + 1;
        let start = self.write_idx.fetch_add(len, Ordering::Relaxed) % RING_BYTES;
        // SAFETY: UnsafeCell permits interior mutability; SPSC approximation.
        let p = self.buf.get() as *mut u8;
        unsafe {
            for (i, b) in msg.iter().enumerate() {
                *p.add((start + i) % RING_BYTES) = *b;
            }
            *p.add((start + msg.len()) % RING_BYTES) = b'\n';
        }
    }

    /// Read the (approximate) current ring contents up to `len` bytes from index 0.
    /// Useful for tests; not for production hot-path use.
    pub fn dump(&self, out: &mut [u8]) -> usize {
        let n = out
            .len()
            .min(self.write_idx.load(Ordering::Relaxed))
            .min(RING_BYTES);
        // SAFETY: reading from UnsafeCell buf; SPSC approximation.
        let p = self.buf.get() as *const u8;
        unsafe {
            core::ptr::copy_nonoverlapping(p, out.as_mut_ptr(), n);
        }
        n
    }
}
