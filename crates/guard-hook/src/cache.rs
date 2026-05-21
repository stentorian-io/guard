//! Per-process bounded LRU getaddrinfo-cache (D-17).
//!
//! v0.1 size: 32 entries. NO HashMap — linear-probe + LRU bumping over a
//! fixed-size array.
//!
//! Key: up to MAX_SOCKADDR_BYTES bytes of canonicalized sockaddr.
//! Value: up to MAX_HOSTNAME bytes of host name.

use core::sync::atomic::{AtomicU64, Ordering};

pub const CAPACITY: usize = 32;
pub const MAX_SOCKADDR_BYTES: usize = 28; // sockaddr_in6 size on Darwin
pub const MAX_HOSTNAME: usize = 253; // RFC 1035 hostname max + room

#[derive(Clone, Copy)]
struct Entry {
    sockaddr_len: u8,
    sockaddr: [u8; MAX_SOCKADDR_BYTES],
    hostname_len: u16,
    hostname: [u8; MAX_HOSTNAME],
    last_use_tick: u64,
}

impl Entry {
    const EMPTY: Entry = Entry {
        sockaddr_len: 0,
        sockaddr: [0; MAX_SOCKADDR_BYTES],
        hostname_len: 0,
        hostname: [0; MAX_HOSTNAME],
        last_use_tick: 0,
    };
}

pub struct Cache {
    entries: [Entry; CAPACITY],
    tick: AtomicU64,
}

impl Cache {
    pub const fn new() -> Self {
        Self {
            entries: [Entry::EMPTY; CAPACITY],
            tick: AtomicU64::new(1),
        }
    }

    fn next_tick(&self) -> u64 {
        self.tick.fetch_add(1, Ordering::Relaxed)
    }

    /// Insert (sockaddr_bytes, hostname). If full, evicts the LRU entry.
    pub fn insert(&mut self, sockaddr: &[u8], hostname: &[u8]) {
        if sockaddr.len() > MAX_SOCKADDR_BYTES {
            return;
        }
        if hostname.len() > MAX_HOSTNAME {
            return;
        }
        // First, see if we already have it (update path).
        if let Some(idx) = self.find_idx(sockaddr) {
            let now = self.next_tick();
            let e = &mut self.entries[idx];
            e.hostname_len = hostname.len() as u16;
            e.hostname[..hostname.len()].copy_from_slice(hostname);
            e.last_use_tick = now;
            return;
        }
        // Find an empty slot or LRU.
        let mut target_idx = 0usize;
        let mut min_tick = u64::MAX;
        for (i, e) in self.entries.iter().enumerate() {
            if e.sockaddr_len == 0 {
                target_idx = i;
                break;
            }
            if e.last_use_tick < min_tick {
                min_tick = e.last_use_tick;
                target_idx = i;
            }
        }
        let now = self.next_tick();
        let e = &mut self.entries[target_idx];
        e.sockaddr_len = sockaddr.len() as u8;
        e.sockaddr[..sockaddr.len()].copy_from_slice(sockaddr);
        e.hostname_len = hostname.len() as u16;
        e.hostname[..hostname.len()].copy_from_slice(hostname);
        e.last_use_tick = now;
    }

    /// Lookup; bumps the entry to most-recently-used on hit.
    pub fn lookup(&mut self, sockaddr: &[u8]) -> Option<&[u8]> {
        let idx = self.find_idx(sockaddr)?;
        let now = self.next_tick();
        self.entries[idx].last_use_tick = now;
        let e = &self.entries[idx];
        Some(&e.hostname[..e.hostname_len as usize])
    }

    fn find_idx(&self, sockaddr: &[u8]) -> Option<usize> {
        for (i, e) in self.entries.iter().enumerate() {
            if e.sockaddr_len as usize == sockaddr.len()
                && &e.sockaddr[..e.sockaddr_len as usize] == sockaddr
            {
                return Some(i);
            }
        }
        None
    }
}

impl Default for Cache {
    fn default() -> Self {
        Self::new()
    }
}
