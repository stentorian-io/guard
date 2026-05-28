//! Linux ELF exec-target boundary for LD_PRELOAD enforcement.
//!
//! ELF structural classification is not supported yet. Linux must not reuse
//! Mach-O clean-unknown decisions, so non-script exec targets fail closed until
//! an ELF scanner exists.

use crate::{macho_flags, trusted_runtime};
use trusted_runtime::TrustedRuntimeRegistry;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BinaryTier {
    T0Blocked(BlockReason),
    T1TrustedRuntime,
    T2AllowedScript,
    T2CleanNativeMachO,
    T3SuspiciousUnknown(SuspiciousReason),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlockReason {
    HardenedRuntime,
    PrivilegeEscalation,
    FatBinary,
    UnsupportedArch,
    UnsupportedSubtype,
    UnsupportedElf,
    UnknownFormat,
    UnreadablePath,
    HeaderReadFailure,
    MalformedMachO,
    ScanFailure,
}

impl BlockReason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::HardenedRuntime => "hardened-runtime",
            Self::PrivilegeEscalation => "privilege-escalation",
            Self::FatBinary => "fat-binary",
            Self::UnsupportedArch => "unsupported-arch",
            Self::UnsupportedSubtype => "unsupported-subtype",
            Self::UnsupportedElf => "unsupported-elf",
            Self::UnknownFormat => "unknown-format",
            Self::UnreadablePath => "unreadable-path",
            Self::HeaderReadFailure => "header-read-failure",
            Self::MalformedMachO => "malformed-macho",
            Self::ScanFailure => "scan-failure",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SuspiciousReason {
    SyscallInstruction,
}

impl SuspiciousReason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::SyscallInstruction => "syscall-instruction",
        }
    }
}

pub fn classify_path(path: *const libc::c_char) -> BinaryTier {
    classify_path_with_registry(path, trusted_runtime::registry())
}

pub fn classify_path_with_registry(
    path: *const libc::c_char,
    _trusted_registry: &TrustedRuntimeRegistry,
) -> BinaryTier {
    if path.is_null() {
        return BinaryTier::T0Blocked(BlockReason::UnreadablePath);
    }

    if macho_flags::is_setuid(path) {
        return BinaryTier::T0Blocked(BlockReason::PrivilegeEscalation);
    }

    let mut header = [0u8; 4];
    let fd = unsafe { libc::open(path, libc::O_RDONLY) };
    if fd < 0 {
        return BinaryTier::T0Blocked(BlockReason::UnreadablePath);
    }

    let n = unsafe { libc::read(fd, header.as_mut_ptr() as *mut libc::c_void, header.len()) };

    unsafe {
        libc::close(fd);
    }

    if n < 0 {
        return BinaryTier::T0Blocked(BlockReason::HeaderReadFailure);
    }

    if n >= 2 && header.starts_with(b"#!") {
        return BinaryTier::T2AllowedScript;
    }

    if n as usize == header.len() && header == *b"\x7fELF" {
        return BinaryTier::T0Blocked(BlockReason::UnsupportedElf);
    }

    BinaryTier::T0Blocked(BlockReason::UnknownFormat)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CString;
    use std::io::Write;
    use std::os::unix::ffi::OsStrExt;

    fn write_temp(contents: &[u8]) -> tempfile::NamedTempFile {
        let mut file = tempfile::NamedTempFile::new().expect("temp file");
        file.write_all(contents).expect("write temp file");
        file
    }

    fn path_cstring(file: &tempfile::NamedTempFile) -> CString {
        CString::new(file.path().as_os_str().as_bytes()).expect("path cstring")
    }

    #[test]
    fn classify_path_allows_shebang_scripts() {
        let file = write_temp(b"#!/bin/sh\nexit 0\n");
        let path = path_cstring(&file);

        assert_eq!(classify_path(path.as_ptr()), BinaryTier::T2AllowedScript);
    }

    #[test]
    fn classify_path_blocks_elf_until_scanner_is_supported() {
        let file = write_temp(b"\x7fELF\x02\x01\x01");
        let path = path_cstring(&file);

        assert_eq!(
            classify_path(path.as_ptr()),
            BinaryTier::T0Blocked(BlockReason::UnsupportedElf)
        );
    }

    #[test]
    fn classify_path_does_not_allow_clean_macho_on_linux() {
        let mut data = vec![0u8; 0x104];
        data[0..4].copy_from_slice(&0xfeedfacfu32.to_le_bytes());

        let file = write_temp(&data);
        let path = path_cstring(&file);

        assert_eq!(
            classify_path(path.as_ptr()),
            BinaryTier::T0Blocked(BlockReason::UnknownFormat)
        );
    }
}
