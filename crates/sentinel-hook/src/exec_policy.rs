//! Exec-time policy for issue #1 layered enforcement phase 1.
//!
//! Classification is based on structural facts about the target binary. T0
//! targets are blocked before exec. T3 targets are logged in detection-only
//! mode for this phase; ptrace enforcement is a later phase.

use crate::log_buffer::LOG_RING;
use crate::macho_scan::{self, BinaryTier, BlockReason};

pub enum ExecDecision {
    Allow,
    Block(BlockReason),
}

pub fn check_exec_target(path: *const libc::c_char) -> ExecDecision {
    match macho_scan::classify_path(path) {
        BinaryTier::T0Blocked(reason) => ExecDecision::Block(reason),
        BinaryTier::T3SuspiciousUnknown(reason) => {
            let mut path_buf = [0u8; 512];
            let n = extract_path(path, &mut path_buf);
            let line = format!(
                "[sentinel-hook] detection-only: T3 suspicious binary reason={} path={}",
                reason.as_str(),
                String::from_utf8_lossy(&path_buf[..n])
            );
            LOG_RING.append(line.as_bytes());
            ExecDecision::Allow
        }
        BinaryTier::T1TrustedRuntime | BinaryTier::T2CleanUnknown => ExecDecision::Allow,
    }
}

fn extract_path(path: *const libc::c_char, out: &mut [u8]) -> usize {
    if path.is_null() || out.is_empty() {
        return 0;
    }
    let mut len = 0;
    loop {
        let b = unsafe { *path.add(len) } as u8;
        if b == 0 {
            break;
        }
        if len == out.len() {
            break;
        }
        out[len] = b;
        len += 1;
    }
    len
}
