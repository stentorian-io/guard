//! Compatibility re-export for the exec-target scanner.
//!
//! macOS callers get Mach-O classification through `scanner::macho`; Linux
//! callers get the explicit ELF/LD_PRELOAD boundary through `scanner`.

#[cfg(target_os = "macos")]
pub use crate::scanner::macho::*;
