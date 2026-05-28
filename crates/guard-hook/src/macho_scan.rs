//! Mach-O structural scanner for layered enforcement phase 1.
//!
//! This module classifies exec targets by facts about the file on disk:
//! Mach-O shape, native architecture, content hash, and syscall instruction
//! bytes in executable `__TEXT` segments. It intentionally does not cache any
//! behavioral observation about a process run.

use crate::trusted_runtime::TrustedRuntimeRegistry;
use crate::{macho_flags, raw_syscall, trusted_runtime};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};

const MH_MAGIC_64: u32 = 0xfeedfacf;
const MH_CIGAM_64: u32 = 0xcffaedfe;
const FAT_MAGIC: u32 = 0xcafebabe;
const FAT_CIGAM: u32 = 0xbebafeca;
const FAT_MAGIC_64: u32 = 0xcafebabf;
const FAT_CIGAM_64: u32 = 0xbfbafeca;
const LC_SEGMENT_64: u32 = 0x19;
const CPU_SUBTYPE_MASK: u32 = 0xff00_0000;
const CPU_SUBTYPE_ARM64_ALL: u32 = 0;
const CPU_SUBTYPE_X86_64_ALL: u32 = 3;
const CPU_SUBTYPE_X86_64_H: u32 = 8;

#[cfg(target_arch = "aarch64")]
const NATIVE_CPU_TYPE: u32 = 0x0100_000c;
#[cfg(target_arch = "x86_64")]
const NATIVE_CPU_TYPE: u32 = 0x0100_0007;

const CPU_TYPE_ARM64: u32 = 0x0100_000c;
const CPU_TYPE_X86_64: u32 = 0x0100_0007;
const MAX_HEADER_READ: usize = 256 * 1024;
const SCAN_CHUNK: usize = 64 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BinaryTier {
    T0Blocked(BlockReason),
    T1TrustedRuntime,
    T2CleanUnknown,
    T3SuspiciousUnknown(SuspiciousReason),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlockReason {
    HardenedRuntime,
    PrivilegeEscalation,
    FatBinary,
    UnsupportedArch,
    UnsupportedSubtype,
    UnknownFormat,
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
            Self::UnknownFormat => "unknown-format",
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ScanVerdict {
    Clean,
    Suspicious(SuspiciousReason),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HeaderKind {
    Fat,
    Script,
    UnknownFormat,
    UnsupportedMachO,
    MalformedMachO,
    Thin64 {
        cputype: u32,
        cpusubtype: u32,
        ncmds: usize,
    },
}

pub fn classify_path(path: *const libc::c_char) -> BinaryTier {
    classify_path_with_registry(path, trusted_runtime::registry())
}

pub fn classify_path_with_registry(
    path: *const libc::c_char,
    trusted_registry: &TrustedRuntimeRegistry,
) -> BinaryTier {
    if path.is_null() {
        return BinaryTier::T2CleanUnknown;
    }

    if let Some(shed_reason) = macho_flags::will_shed_dylib(path) {
        let reason = match shed_reason {
            macho_flags::ShedReason::Setuid => BlockReason::PrivilegeEscalation,
            macho_flags::ShedReason::CodeSign => BlockReason::HardenedRuntime,
        };
        return BinaryTier::T0Blocked(reason);
    }

    let fd = unsafe { libc::open(path, libc::O_RDONLY) };
    if fd < 0 {
        return BinaryTier::T2CleanUnknown;
    }
    let mut header = [0u8; MAX_HEADER_READ];
    let n = unsafe {
        raw_syscall::raw_read(fd, header.as_mut_ptr() as *mut libc::c_void, header.len())
    };
    unsafe {
        libc::close(fd);
    }
    match parse_header_kind(&header[..n as usize]) {
        HeaderKind::Fat => BinaryTier::T0Blocked(BlockReason::FatBinary),
        HeaderKind::Script => BinaryTier::T2CleanUnknown,
        HeaderKind::UnknownFormat => BinaryTier::T0Blocked(BlockReason::UnknownFormat),
        HeaderKind::UnsupportedMachO => BinaryTier::T0Blocked(BlockReason::UnsupportedArch),
        HeaderKind::MalformedMachO => BinaryTier::T0Blocked(BlockReason::MalformedMachO),
        HeaderKind::Thin64 {
            cputype,
            cpusubtype,
            ..
        } => {
            if cputype != NATIVE_CPU_TYPE || !is_supported_cpu(cputype) {
                return BinaryTier::T0Blocked(BlockReason::UnsupportedArch);
            }

            if !is_supported_cpu_subtype(cputype, cpusubtype) {
                return BinaryTier::T0Blocked(BlockReason::UnsupportedSubtype);
            }

            match hash_file(path) {
                Some(hash) if trusted_registry.get(&hash).is_some() => BinaryTier::T1TrustedRuntime,
                Some(hash) => match cached_or_scan(path, hash) {
                    Some(ScanVerdict::Clean) => BinaryTier::T2CleanUnknown,
                    Some(ScanVerdict::Suspicious(reason)) => {
                        BinaryTier::T3SuspiciousUnknown(reason)
                    }
                    None => BinaryTier::T0Blocked(BlockReason::ScanFailure),
                },
                None => BinaryTier::T0Blocked(BlockReason::ScanFailure),
            }
        }
    }
}

fn cached_or_scan(path: *const libc::c_char, hash: [u8; 32]) -> Option<ScanVerdict> {
    let cache = scan_cache();
    if let Some(verdict) = cache.lock().expect("macho scan cache").get(&hash).copied() {
        return Some(verdict);
    }
    let verdict = scan_path(path)?;
    cache
        .lock()
        .expect("macho scan cache")
        .insert(hash, verdict);
    Some(verdict)
}

fn scan_cache() -> &'static Mutex<HashMap<[u8; 32], ScanVerdict>> {
    static CACHE: OnceLock<Mutex<HashMap<[u8; 32], ScanVerdict>>> = OnceLock::new();
    CACHE.get_or_init(|| Mutex::new(HashMap::new()))
}

fn hash_file(path: *const libc::c_char) -> Option<[u8; 32]> {
    let fd = unsafe { libc::open(path, libc::O_RDONLY) };
    if fd < 0 {
        return None;
    }
    let mut hasher = Sha256::new();
    let mut buf = [0u8; SCAN_CHUNK];
    loop {
        let n =
            unsafe { raw_syscall::raw_read(fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len()) };
        if n < 0 {
            unsafe {
                libc::close(fd);
            }
            return None;
        }
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n as usize]);
    }
    unsafe {
        libc::close(fd);
    }
    Some(hasher.finalize().into())
}

fn scan_path(path: *const libc::c_char) -> Option<ScanVerdict> {
    let fd = unsafe { libc::open(path, libc::O_RDONLY) };
    if fd < 0 {
        return None;
    }
    let mut header = [0u8; MAX_HEADER_READ];
    let n = unsafe {
        raw_syscall::raw_read(fd, header.as_mut_ptr() as *mut libc::c_void, header.len())
    };
    if n < 32 {
        unsafe {
            libc::close(fd);
        }
        return None;
    }
    let ranges = text_ranges(&header[..n as usize])?;
    for (fileoff, filesize) in ranges {
        match scan_file_range(fd, fileoff, filesize) {
            Some(true) => {
                unsafe {
                    libc::close(fd);
                }
                return Some(ScanVerdict::Suspicious(
                    SuspiciousReason::SyscallInstruction,
                ));
            }
            Some(false) => {}
            None => {
                unsafe {
                    libc::close(fd);
                }
                return None;
            }
        }
    }
    unsafe {
        libc::close(fd);
    }
    Some(ScanVerdict::Clean)
}

fn scan_file_range(fd: libc::c_int, fileoff: u64, filesize: u64) -> Option<bool> {
    if filesize == 0 {
        return Some(false);
    }
    let seeked = unsafe { libc::lseek(fd, fileoff as libc::off_t, libc::SEEK_SET) };
    if seeked < 0 {
        return None;
    }

    let mut remaining = filesize;
    let mut buf = [0u8; SCAN_CHUNK + 3];
    let mut tail_len = 0usize;
    while remaining > 0 {
        let want = (remaining as usize).min(SCAN_CHUNK);
        let n = unsafe {
            raw_syscall::raw_read(fd, buf[tail_len..].as_mut_ptr() as *mut libc::c_void, want)
        };
        if n <= 0 {
            return None;
        }
        let total = tail_len + n as usize;
        if contains_syscall_pattern(&buf[..total]) {
            return Some(true);
        }
        tail_len = total.min(3);
        buf.copy_within(total - tail_len..total, 0);
        remaining -= n as u64;
    }
    Some(false)
}

fn parse_header_kind(data: &[u8]) -> HeaderKind {
    if data.len() < 4 {
        if data.starts_with(b"#!") {
            return HeaderKind::Script;
        }

        return HeaderKind::UnknownFormat;
    }
    let be_magic = u32::from_be_bytes(data[0..4].try_into().unwrap());
    if matches!(
        be_magic,
        FAT_MAGIC | FAT_CIGAM | FAT_MAGIC_64 | FAT_CIGAM_64
    ) {
        return HeaderKind::Fat;
    }
    let le_magic = u32::from_le_bytes(data[0..4].try_into().unwrap());
    if le_magic == MH_CIGAM_64 {
        return HeaderKind::UnsupportedMachO;
    }
    if le_magic != MH_MAGIC_64 {
        if data.starts_with(b"#!") {
            return HeaderKind::Script;
        }

        return HeaderKind::UnknownFormat;
    }
    if data.len() < 32 {
        return HeaderKind::MalformedMachO;
    }
    let cputype = u32::from_le_bytes(data[4..8].try_into().unwrap());
    let cpusubtype = u32::from_le_bytes(data[8..12].try_into().unwrap());
    let ncmds = u32::from_le_bytes(data[16..20].try_into().unwrap()) as usize;
    HeaderKind::Thin64 {
        cputype,
        cpusubtype,
        ncmds,
    }
}

fn text_ranges(data: &[u8]) -> Option<Vec<(u64, u64)>> {
    let HeaderKind::Thin64 { ncmds, .. } = parse_header_kind(data) else {
        return None;
    };
    let mut ranges = Vec::new();
    let mut pos = 32usize;
    for _ in 0..ncmds.min(512) {
        if pos + 72 > data.len() {
            return None;
        }
        let cmd = u32::from_le_bytes(data[pos..pos + 4].try_into().unwrap());
        let cmdsize = u32::from_le_bytes(data[pos + 4..pos + 8].try_into().unwrap()) as usize;
        if cmdsize < 8 || pos + cmdsize > data.len() {
            return None;
        }
        if cmd == LC_SEGMENT_64 && cmdsize >= 72 {
            let segname = &data[pos + 8..pos + 24];
            if nul_trim(segname) == b"__TEXT" {
                let fileoff = u64::from_le_bytes(data[pos + 40..pos + 48].try_into().unwrap());
                let filesize = u64::from_le_bytes(data[pos + 48..pos + 56].try_into().unwrap());
                ranges.push((fileoff, filesize));
            }
        }
        pos += cmdsize;
    }
    Some(ranges)
}

fn nul_trim(bytes: &[u8]) -> &[u8] {
    match bytes.iter().position(|b| *b == 0) {
        Some(n) => &bytes[..n],
        None => bytes,
    }
}

fn is_supported_cpu(cputype: u32) -> bool {
    matches!(cputype, CPU_TYPE_ARM64 | CPU_TYPE_X86_64)
}

fn is_supported_cpu_subtype(cputype: u32, cpusubtype: u32) -> bool {
    let subtype = cpusubtype & !CPU_SUBTYPE_MASK;

    match cputype {
        CPU_TYPE_ARM64 => subtype == CPU_SUBTYPE_ARM64_ALL,
        CPU_TYPE_X86_64 => matches!(subtype, CPU_SUBTYPE_X86_64_ALL | CPU_SUBTYPE_X86_64_H),
        _ => false,
    }
}

fn contains_syscall_pattern(bytes: &[u8]) -> bool {
    bytes.windows(4).any(|w| w == [0x01, 0x10, 0x00, 0xd4])
        || bytes
            .windows(2)
            .any(|w| w == [0x0f, 0x05] || w == [0xcd, 0x80])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::trusted_runtime::TrustedRuntimeRegistry;
    use sha2::{Digest, Sha256};
    use std::ffi::CString;
    use std::io::Write;
    use std::os::unix::ffi::OsStrExt;

    fn thin_header(cputype: u32, cpusubtype: u32, text_payload: &[u8]) -> Vec<u8> {
        let fileoff = 0x100u64;
        let filesize = text_payload.len() as u64;
        let mut data = vec![0u8; fileoff as usize + text_payload.len()];
        data[0..4].copy_from_slice(&MH_MAGIC_64.to_le_bytes());
        data[4..8].copy_from_slice(&cputype.to_le_bytes());
        data[8..12].copy_from_slice(&cpusubtype.to_le_bytes());
        data[16..20].copy_from_slice(&1u32.to_le_bytes());
        data[20..24].copy_from_slice(&72u32.to_le_bytes());
        let pos = 32usize;
        data[pos..pos + 4].copy_from_slice(&LC_SEGMENT_64.to_le_bytes());
        data[pos + 4..pos + 8].copy_from_slice(&72u32.to_le_bytes());
        data[pos + 8..pos + 14].copy_from_slice(b"__TEXT");
        data[pos + 40..pos + 48].copy_from_slice(&fileoff.to_le_bytes());
        data[pos + 48..pos + 56].copy_from_slice(&filesize.to_le_bytes());
        data[fileoff as usize..].copy_from_slice(text_payload);
        data
    }

    fn write_temp(contents: &[u8]) -> tempfile::NamedTempFile {
        let mut file = tempfile::NamedTempFile::new().expect("temp file");
        file.write_all(contents).expect("write temp file");
        file
    }

    fn path_cstring(file: &tempfile::NamedTempFile) -> CString {
        CString::new(file.path().as_os_str().as_bytes()).expect("path cstring")
    }

    fn native_cpu_subtype() -> u32 {
        #[cfg(target_arch = "aarch64")]
        {
            CPU_SUBTYPE_ARM64_ALL
        }

        #[cfg(target_arch = "x86_64")]
        {
            CPU_SUBTYPE_X86_64_ALL
        }
    }

    #[test]
    fn detects_fat_magic() {
        let mut data = [0u8; 8];
        data[0..4].copy_from_slice(&FAT_MAGIC.to_be_bytes());
        assert_eq!(parse_header_kind(&data), HeaderKind::Fat);
    }

    #[test]
    fn classify_path_blocks_fat_binary() {
        let mut data = [0u8; 8];
        data[0..4].copy_from_slice(&FAT_MAGIC.to_be_bytes());
        let file = write_temp(&data);
        let path = path_cstring(&file);
        assert_eq!(
            classify_path(path.as_ptr()),
            BinaryTier::T0Blocked(BlockReason::FatBinary)
        );
    }

    #[test]
    fn classify_path_detects_suspicious_thin_binary() {
        let data = thin_header(
            NATIVE_CPU_TYPE,
            native_cpu_subtype(),
            &[0xaa, 0x01, 0x10, 0x00, 0xd4],
        );
        let file = write_temp(&data);
        let path = path_cstring(&file);
        assert_eq!(
            classify_path(path.as_ptr()),
            BinaryTier::T3SuspiciousUnknown(SuspiciousReason::SyscallInstruction)
        );
    }

    #[test]
    fn classify_path_promotes_trusted_runtime_before_syscall_scan() {
        let data = thin_header(
            NATIVE_CPU_TYPE,
            native_cpu_subtype(),
            &[0xaa, 0x01, 0x10, 0x00, 0xd4],
        );
        let hash = Sha256::digest(&data);
        let registry_yaml = format!(
            "runtimes:\n  - sha256: \"{}\"\n    name: guard-test-runtime\n    version: \"0.0.0\"\n    source: unit-test\n",
            hash.iter().map(|b| format!("{b:02x}")).collect::<String>()
        );
        let registry = TrustedRuntimeRegistry::parse(&registry_yaml);
        let file = write_temp(&data);
        let path = path_cstring(&file);
        assert_eq!(
            classify_path_with_registry(path.as_ptr(), &registry),
            BinaryTier::T1TrustedRuntime
        );
    }

    #[test]
    fn classify_path_allows_shebang_scripts() {
        let file = write_temp(b"#!/bin/sh\nexit 0\n");
        let path = path_cstring(&file);
        assert_eq!(classify_path(path.as_ptr()), BinaryTier::T2CleanUnknown);
    }

    #[test]
    fn classify_path_blocks_unknown_non_macho_files() {
        let file = write_temp(b"not a script or Mach-O");
        let path = path_cstring(&file);
        assert_eq!(
            classify_path(path.as_ptr()),
            BinaryTier::T0Blocked(BlockReason::UnknownFormat)
        );
    }

    #[test]
    fn classify_path_blocks_unknown_native_cpu_subtype() {
        let data = thin_header(NATIVE_CPU_TYPE, 0x0000_00fe, &[1, 2, 3, 4]);
        let file = write_temp(&data);
        let path = path_cstring(&file);
        assert_eq!(
            classify_path(path.as_ptr()),
            BinaryTier::T0Blocked(BlockReason::UnsupportedSubtype)
        );
    }

    #[test]
    fn classify_path_blocks_unsupported_cpu_type() {
        let data = thin_header(
            0x0100_000c ^ 0x0000_000b,
            native_cpu_subtype(),
            &[1, 2, 3, 4],
        );
        let file = write_temp(&data);
        let path = path_cstring(&file);
        assert_eq!(
            classify_path(path.as_ptr()),
            BinaryTier::T0Blocked(BlockReason::UnsupportedArch)
        );
    }

    #[test]
    fn classify_path_blocks_malformed_macho_load_command() {
        let mut data = thin_header(NATIVE_CPU_TYPE, native_cpu_subtype(), &[1, 2, 3, 4]);
        data[32 + 4..32 + 8].copy_from_slice(&4u32.to_le_bytes());
        let file = write_temp(&data);
        let path = path_cstring(&file);
        assert_eq!(
            classify_path(path.as_ptr()),
            BinaryTier::T0Blocked(BlockReason::ScanFailure)
        );
    }

    #[test]
    fn extracts_text_range_from_thin_macho() {
        let data = thin_header(NATIVE_CPU_TYPE, native_cpu_subtype(), &[1, 2, 3, 4]);
        assert_eq!(text_ranges(&data), Some(vec![(0x100, 4)]));
    }

    #[test]
    fn detects_supported_syscall_patterns() {
        assert!(contains_syscall_pattern(&[0xaa, 0x01, 0x10, 0x00, 0xd4]));
        assert!(contains_syscall_pattern(&[0xaa, 0x0f, 0x05]));
        assert!(contains_syscall_pattern(&[0xaa, 0xcd, 0x80]));
        assert!(!contains_syscall_pattern(&[0xaa, 0x0f, 0x04, 0xcd, 0x81]));
    }

    #[test]
    fn block_reason_as_str_privilege_escalation() {
        assert_eq!(
            BlockReason::PrivilegeEscalation.as_str(),
            "privilege-escalation"
        );
        assert_eq!(BlockReason::HardenedRuntime.as_str(), "hardened-runtime");
        assert_eq!(BlockReason::FatBinary.as_str(), "fat-binary");
        assert_eq!(BlockReason::UnsupportedArch.as_str(), "unsupported-arch");
        assert_eq!(
            BlockReason::UnsupportedSubtype.as_str(),
            "unsupported-subtype"
        );
        assert_eq!(BlockReason::UnknownFormat.as_str(), "unknown-format");
        assert_eq!(BlockReason::MalformedMachO.as_str(), "malformed-macho");
        assert_eq!(BlockReason::ScanFailure.as_str(), "scan-failure");
    }

    #[test]
    fn classify_system_sudo_blocks_as_privilege_escalation() {
        // /usr/bin/sudo is setuid on macOS — it should be blocked with
        // PrivilegeEscalation, not HardenedRuntime.
        let path = CString::new("/usr/bin/sudo").unwrap();
        let tier = classify_path(path.as_ptr());
        // sudo is both setuid AND a platform binary; the setuid check runs
        // first in will_shed_dylib, so we expect PrivilegeEscalation.
        assert_eq!(
            tier,
            BinaryTier::T0Blocked(BlockReason::PrivilegeEscalation)
        );
    }

    #[test]
    fn classify_system_ls_blocks_as_hardened_runtime() {
        // /bin/ls is a platform binary with CS_RUNTIME but NOT setuid.
        let path = CString::new("/bin/ls").unwrap();
        let tier = classify_path(path.as_ptr());
        assert_eq!(tier, BinaryTier::T0Blocked(BlockReason::HardenedRuntime));
    }
}
