//! Exec target scanner selected by OS boundary.
//!
//! macOS has supported Mach-O/DYLD classification. Linux intentionally does
//! not reuse that scanner for `ELF/LD_PRELOAD` exec targets.

#[cfg(target_os = "linux")]
mod elf;
#[cfg(target_os = "macos")]
pub mod macho;

#[cfg(target_os = "linux")]
pub use elf::{BinaryTier, BlockReason, SuspiciousReason, classify_path};
#[cfg(target_os = "macos")]
pub use macho::{BinaryTier, BlockReason, SuspiciousReason, classify_path};

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
mod unsupported {
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum BinaryTier {
        T0Blocked(BlockReason),
        T2AllowedScript,
        T2CleanNativeMachO,
        T3SuspiciousUnknown(SuspiciousReason),
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum BlockReason {
        UnsupportedPlatform,
    }

    impl BlockReason {
        pub fn as_str(self) -> &'static str {
            "unsupported-platform"
        }
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum SuspiciousReason {
        UnsupportedPlatform,
    }

    impl SuspiciousReason {
        pub fn as_str(self) -> &'static str {
            "unsupported-platform"
        }
    }

    pub fn classify_path(_path: *const libc::c_char) -> BinaryTier {
        BinaryTier::T0Blocked(BlockReason::UnsupportedPlatform)
    }
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
pub use unsupported::{BinaryTier, BlockReason, SuspiciousReason, classify_path};
