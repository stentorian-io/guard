//! Exec-time policy for issue #1 layered enforcement.
//!
//! Classification is based on structural facts about the target binary. T0
//! targets are blocked before exec. T3 targets fail closed before child
//! creation; non-fail-closed alternatives are tracked separately.

use crate::macho_scan::{self, BinaryTier, BlockReason, SuspiciousReason};

pub enum ExecDecision {
    Allow,
    Block(BlockReason),
    Trace(SuspiciousReason),
}

pub fn check_exec_target(path: *const libc::c_char) -> ExecDecision {
    match macho_scan::classify_path(path) {
        BinaryTier::T0Blocked(reason) => ExecDecision::Block(reason),
        BinaryTier::T3SuspiciousUnknown(reason) => ExecDecision::Trace(reason),
        BinaryTier::T1TrustedRuntime | BinaryTier::T2CleanUnknown => ExecDecision::Allow,
    }
}
