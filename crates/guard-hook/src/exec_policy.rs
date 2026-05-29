//! Exec-time policy for issue #1 layered enforcement.
//!
//! Classification is based on structural facts about the target binary. T0
//! targets are blocked before exec. T3 targets fail closed before child
//! creation; non-fail-closed alternatives are tracked separately.

use crate::scanner::{self, BinaryTier, BlockReason, SuspiciousReason};

pub enum ExecDecision {
    Allow,
    Block(BlockReason),
    Trace(SuspiciousReason),
}

#[must_use]
/// Evaluate exec-time policy for a target path.
///
/// # Safety
///
/// `path` must either be null or point to a valid NUL-terminated C string.
pub unsafe fn check_exec_target(path: *const libc::c_char) -> ExecDecision {
    match unsafe { scanner::classify_path(path) } {
        BinaryTier::T0Blocked(reason) => ExecDecision::Block(reason),
        BinaryTier::T3SuspiciousUnknown(reason) => ExecDecision::Trace(reason),
        BinaryTier::T1TrustedRuntime
        | BinaryTier::T2AllowedScript
        | BinaryTier::T2CleanNativeMachO => ExecDecision::Allow,
    }
}
