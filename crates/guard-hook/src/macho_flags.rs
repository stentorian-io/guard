//! Mach-O code-signing analysis for hardened-runtime exec blocking.
//!
//! Determines whether a target binary will shed the DYLD interpose library.
//! macOS strips `DYLD_INSERT_LIBRARIES` for:
//!   - Platform binaries (Apple system binaries with Platform identifier > 0)
//!   - Binaries with `CS_RESTRICT` or `CS_RUNTIME` in `CodeDirectory` flags
//!   - setuid/setgid binaries
//!
//! This module reads the binary's Mach-O headers on disk to check these
//! conditions BEFORE exec, without spawning a subprocess.

use crate::raw_syscall;

const MH_MAGIC_64: u32 = 0xfeed_facf;
const FAT_MAGIC: u32 = 0xcafe_babe;
const FAT_CIGAM: u32 = 0xbeba_feca;
const FAT_MAGIC_64: u32 = 0xcafe_babf;
const FAT_CIGAM_64: u32 = 0xbfba_feca;

const LC_CODE_SIGNATURE: u32 = 0x1d;

const CSMAGIC_EMBEDDED_SIGNATURE: u32 = 0xfade_0cc0;
const CSMAGIC_CODEDIRECTORY: u32 = 0xfade_0c02;

pub const CS_RUNTIME: u32 = 0x0001_0000;
const CS_RESTRICT: u32 = 0x0000_0800;

#[cfg(target_arch = "aarch64")]
const NATIVE_CPU_TYPE: u32 = 0x0100_000c; // CPU_TYPE_ARM64
#[cfg(target_arch = "x86_64")]
const NATIVE_CPU_TYPE: u32 = 0x0100_0007; // CPU_TYPE_X86_64

const MAX_READ: usize = 64 * 1024;
const MH_RESTRICT: u32 = 0x80;

#[derive(Debug, Clone, Copy)]
pub struct CodeSignInfo {
    pub flags: u32,
    pub platform: u8,
}

impl CodeSignInfo {
    #[must_use]
    pub fn will_shed_dylib(&self) -> bool {
        self.platform > 0 || self.flags & CS_RUNTIME != 0 || self.flags & CS_RESTRICT != 0
    }
}

#[must_use]
/// Check code-signing flags for a Mach-O binary path.
///
/// # Safety
///
/// `path` must either be null or point to a valid NUL-terminated C string.
pub unsafe fn check_binary(path: *const libc::c_char) -> Option<CodeSignInfo> {
    if path.is_null() {
        return None;
    }
    let fd = unsafe { libc::open(path, libc::O_RDONLY) };
    if fd < 0 {
        return None;
    }
    let result = check_fd(fd);
    unsafe { libc::close(fd) };
    result
}

#[must_use]
/// Check whether a path names a setuid or setgid file.
///
/// # Safety
///
/// `path` must either be null or point to a valid NUL-terminated C string.
pub unsafe fn is_setuid(path: *const libc::c_char) -> bool {
    if path.is_null() {
        return false;
    }
    let mut stat_buf: libc::stat = unsafe { core::mem::zeroed() };
    let rc = unsafe { libc::stat(path, &raw mut stat_buf) };
    if rc != 0 {
        return false;
    }
    stat_buf.st_mode & (libc::S_ISUID | libc::S_ISGID) != 0
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShedReason {
    Setuid,
    CodeSign,
}

#[must_use]
/// Determine why executing a binary would shed the injected dylib.
///
/// # Safety
///
/// `path` must either be null or point to a valid NUL-terminated C string.
pub unsafe fn will_shed_dylib(path: *const libc::c_char) -> Option<ShedReason> {
    if unsafe { is_setuid(path) } {
        return Some(ShedReason::Setuid);
    }
    match unsafe { check_binary(path) } {
        Some(info) if info.will_shed_dylib() => Some(ShedReason::CodeSign),
        _ => None,
    }
}

fn check_fd(fd: i32) -> Option<CodeSignInfo> {
    let mut buf = vec![0u8; MAX_READ];
    let n =
        unsafe { raw_syscall::raw_read(fd, buf.as_mut_ptr().cast::<libc::c_void>(), buf.len()) };
    if n < 4 {
        return None;
    }
    let len = usize::try_from(n).ok()?;
    let magic = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]);

    match magic {
        FAT_MAGIC | FAT_CIGAM => check_fat32(&buf[..len], fd),
        FAT_MAGIC_64 | FAT_CIGAM_64 => check_fat64(&buf[..len], fd),
        _ => {
            let le_magic = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]);
            if le_magic == MH_MAGIC_64 {
                check_macho64(&buf[..len], fd, 0)
            } else {
                None
            }
        }
    }
}

fn check_fat32(header: &[u8], fd: i32) -> Option<CodeSignInfo> {
    if header.len() < 8 {
        return None;
    }
    let nfat = u32::from_be_bytes([header[4], header[5], header[6], header[7]]);
    let nfat = usize::try_from(nfat.min(16)).ok()?;

    for i in 0..nfat {
        let off = 8 + i * 20;
        if off + 20 > header.len() {
            break;
        }
        let cputype = u32::from_be_bytes([
            header[off],
            header[off + 1],
            header[off + 2],
            header[off + 3],
        ]);
        let slice_offset = u32::from_be_bytes([
            header[off + 8],
            header[off + 9],
            header[off + 10],
            header[off + 11],
        ]);
        if cputype == NATIVE_CPU_TYPE {
            return check_macho_at_offset(fd, u64::from(slice_offset));
        }
    }
    None
}

fn check_fat64(header: &[u8], fd: i32) -> Option<CodeSignInfo> {
    if header.len() < 8 {
        return None;
    }
    let nfat = u32::from_be_bytes([header[4], header[5], header[6], header[7]]);
    let nfat = usize::try_from(nfat.min(16)).ok()?;

    for i in 0..nfat {
        let off = 8 + i * 32;
        if off + 32 > header.len() {
            break;
        }
        let cputype = u32::from_be_bytes([
            header[off],
            header[off + 1],
            header[off + 2],
            header[off + 3],
        ]);
        let slice_offset = u64::from_be_bytes([
            header[off + 8],
            header[off + 9],
            header[off + 10],
            header[off + 11],
            header[off + 12],
            header[off + 13],
            header[off + 14],
            header[off + 15],
        ]);
        if cputype == NATIVE_CPU_TYPE {
            return check_macho_at_offset(fd, slice_offset);
        }
    }
    None
}

fn check_macho_at_offset(fd: i32, offset: u64) -> Option<CodeSignInfo> {
    let offset = libc::off_t::try_from(offset).ok()?;
    let seeked = unsafe { libc::lseek(fd, offset, libc::SEEK_SET) };
    if seeked < 0 {
        return None;
    }
    let mut buf = vec![0u8; MAX_READ];
    let n =
        unsafe { raw_syscall::raw_read(fd, buf.as_mut_ptr().cast::<libc::c_void>(), buf.len()) };
    if n < 4 {
        return None;
    }
    let len = usize::try_from(n).ok()?;
    check_macho64(&buf[..len], fd, u64::try_from(offset).ok()?)
}

fn check_macho64(data: &[u8], fd: i32, base_offset: u64) -> Option<CodeSignInfo> {
    if data.len() < 32 {
        return None;
    }
    let magic = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
    if magic != MH_MAGIC_64 {
        return None;
    }
    let mh_flags = u32::from_le_bytes([data[24], data[25], data[26], data[27]]);
    let mh_restricted = mh_flags & MH_RESTRICT != 0;

    let ncmds = u32::from_le_bytes([data[16], data[17], data[18], data[19]]);
    let ncmds = usize::try_from(ncmds.min(256)).ok()?;

    let mut pos = 32; // sizeof(mach_header_64)

    for _ in 0..ncmds {
        if pos + 8 > data.len() {
            break;
        }
        let cmd = u32::from_le_bytes([data[pos], data[pos + 1], data[pos + 2], data[pos + 3]]);
        let cmdsize =
            u32::from_le_bytes([data[pos + 4], data[pos + 5], data[pos + 6], data[pos + 7]]);
        let cmdsize = usize::try_from(cmdsize).ok()?;
        if cmdsize < 8 {
            break;
        }

        if cmd == LC_CODE_SIGNATURE {
            if pos + 16 > data.len() {
                break;
            }
            let dataoff =
                u32::from_le_bytes([data[pos + 8], data[pos + 9], data[pos + 10], data[pos + 11]]);
            if let Some(mut info) = read_code_signature(fd, base_offset + u64::from(dataoff)) {
                if mh_restricted {
                    info.flags |= CS_RESTRICT;
                }
                return Some(info);
            }
            if mh_restricted {
                return Some(CodeSignInfo {
                    flags: CS_RESTRICT,
                    platform: 0,
                });
            }
            return None;
        }

        pos += cmdsize;
    }

    if mh_restricted {
        return Some(CodeSignInfo {
            flags: CS_RESTRICT,
            platform: 0,
        });
    }
    None
}

fn read_code_signature(fd: i32, abs_offset: u64) -> Option<CodeSignInfo> {
    let abs_offset = libc::off_t::try_from(abs_offset).ok()?;
    let seeked = unsafe { libc::lseek(fd, abs_offset, libc::SEEK_SET) };
    if seeked < 0 {
        return None;
    }
    let mut buf = [0u8; 8192];
    let n =
        unsafe { raw_syscall::raw_read(fd, buf.as_mut_ptr().cast::<libc::c_void>(), buf.len()) };
    if n < 12 {
        return None;
    }
    let len = usize::try_from(n).ok()?;

    let magic = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]);
    if magic != CSMAGIC_EMBEDDED_SIGNATURE {
        return None;
    }
    let count = u32::from_be_bytes([buf[8], buf[9], buf[10], buf[11]]);
    let count = usize::try_from(count.min(32)).ok()?;

    for i in 0..count {
        let idx_off = 12 + i * 8;
        if idx_off + 8 > len {
            break;
        }
        let blob_offset = u32::from_be_bytes([
            buf[idx_off + 4],
            buf[idx_off + 5],
            buf[idx_off + 6],
            buf[idx_off + 7],
        ]);
        let blob_offset = usize::try_from(blob_offset).ok()?;
        if blob_offset + 44 > len {
            continue;
        }
        let blob_magic = u32::from_be_bytes([
            buf[blob_offset],
            buf[blob_offset + 1],
            buf[blob_offset + 2],
            buf[blob_offset + 3],
        ]);
        if blob_magic == CSMAGIC_CODEDIRECTORY {
            // CodeDirectory layout (big-endian):
            //   0..4:   magic
            //   4..8:   length
            //   8..12:  version
            //  12..16:  flags
            //  ...
            //  36:      platform (u8) — present in version >= 0x20400
            let flags = u32::from_be_bytes([
                buf[blob_offset + 12],
                buf[blob_offset + 13],
                buf[blob_offset + 14],
                buf[blob_offset + 15],
            ]);
            let version = u32::from_be_bytes([
                buf[blob_offset + 8],
                buf[blob_offset + 9],
                buf[blob_offset + 10],
                buf[blob_offset + 11],
            ]);
            let platform = if version >= 0x20400 && blob_offset + 37 <= len {
                buf[blob_offset + 36]
            } else {
                0
            };
            return Some(CodeSignInfo { flags, platform });
        }
    }
    None
}
