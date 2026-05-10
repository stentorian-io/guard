//! Exec-blocking policy for hardened-runtime binaries.
//!
//! When a tracked process attempts to exec a binary that will shed the
//! DYLD interpose library (platform binary, CS_RUNTIME, setuid), this
//! module decides whether to block or allow the exec.
//!
//! Policy: exec of known network-capable tools (curl, wget, nc, etc.)
//! is BLOCKED because those tools can exfiltrate data without Sentinel's
//! hooks. Other hardened binaries are ALLOWED (gap detector still fires).

use crate::macho_flags;

const BLOCKED_BASENAMES: &[&[u8]] = &[
    b"curl",
    b"wget",
    b"nc",
    b"ncat",
    b"netcat",
    b"fetch",
    b"ftp",
    b"sftp",
    b"ssh",
    b"scp",
    b"telnet",
    b"nscurl",
];

pub enum ExecDecision {
    Allow,
    BlockHardened,
}

pub fn check_exec_target(path: *const libc::c_char) -> ExecDecision {
    if path.is_null() {
        return ExecDecision::Allow;
    }

    if !macho_flags::will_shed_dylib(path) {
        return ExecDecision::Allow;
    }

    let mut basename_buf = [0u8; 256];
    let basename_len = extract_basename(path, &mut basename_buf);
    let basename = &basename_buf[..basename_len];

    for blocked in BLOCKED_BASENAMES {
        if basename == *blocked {
            return ExecDecision::BlockHardened;
        }
    }

    ExecDecision::Allow
}

fn extract_basename(path: *const libc::c_char, out: &mut [u8; 256]) -> usize {
    let mut len = 0usize;
    let mut last_slash = 0usize;
    let mut found_slash = false;

    loop {
        let b = unsafe { *path.add(len) } as u8;
        if b == 0 {
            break;
        }
        if b == b'/' {
            last_slash = len;
            found_slash = true;
        }
        len += 1;
        if len > 4096 {
            break;
        }
    }

    let start = if found_slash { last_slash + 1 } else { 0 };
    if start >= len {
        return 0;
    }
    let name_len = (len - start).min(256);
    unsafe {
        core::ptr::copy_nonoverlapping(path.add(start) as *const u8, out.as_mut_ptr(), name_len);
    }
    name_len
}
