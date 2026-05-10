//! Direct kernel syscall wrappers using inline assembly.
//!
//! These bypass libc::syscall() entirely — libc::syscall is itself an
//! interposable symbol, so once T04 interposes it, the hook's own calls
//! through libc::syscall would recurse. These wrappers go straight to
//! the kernel via `svc #0x80` (aarch64) or the `syscall` instruction
//! (x86_64), avoiding the interpose chain completely.
//!
//! macOS/XNU syscall ABI:
//!   - aarch64: x16 = syscall number, x0-x5 = args, svc #0x80, result in x0
//!   - x86_64:  rax = syscall number | 0x2000000, rdi/rsi/rdx/r10/r8/r9 = args,
//!              syscall instruction, result in rax
//!
//! The 0x2000000 prefix on x86_64 selects the BSD syscall class on XNU.

use core::ffi::{c_int, c_void};
use libc::{msghdr, size_t, sockaddr, socklen_t, ssize_t};

// macOS BSD syscall numbers (stable across versions).
pub const SYS_FORK: i64 = 2;
pub const SYS_WRITE: i64 = 4;
pub const SYS_EXECVE: i64 = 59;
pub const SYS_VFORK: i64 = 66;
pub const SYS_SENDMSG: i64 = 28;
pub const SYS_SENDTO: i64 = 133;
pub const SYS_CONNECT: i64 = 98;
pub const SYS_WRITEV: i64 = 121;
pub const SYS_CONNECTX: i64 = 447;
// SYS_SEND does not exist on macOS/XNU — send() is implemented as
// sendto() with a NULL destination address in libc. We use SYS_SENDTO
// with to=NULL, tolen=0 as the raw equivalent.
pub const SYS_READ: i64 = 3;
pub const SYS_OPEN: i64 = 5;
pub const SYS_GETSOCKOPT: i64 = 118;
pub const SYS_OPENAT: i64 = 463;

/// Raw kernel syscall with 3 arguments.
#[inline(always)]
unsafe fn syscall3(num: i64, a1: u64, a2: u64, a3: u64) -> i64 {
    let ret: i64;
    #[cfg(target_arch = "aarch64")]
    unsafe {
        core::arch::asm!(
            "svc #0x80",
            in("x16") num,
            inout("x0") a1 => ret,
            in("x1") a2,
            in("x2") a3,
            options(nostack),
        );
    }
    #[cfg(target_arch = "x86_64")]
    unsafe {
        core::arch::asm!(
            "syscall",
            inout("rax") num | 0x2000000 => ret,
            in("rdi") a1,
            in("rsi") a2,
            in("rdx") a3,
            out("rcx") _,
            out("r11") _,
            options(nostack),
        );
    }
    ret
}

/// Raw kernel syscall with 4 arguments.
#[inline(always)]
unsafe fn syscall4(num: i64, a1: u64, a2: u64, a3: u64, a4: u64) -> i64 {
    let ret: i64;
    #[cfg(target_arch = "aarch64")]
    unsafe {
        core::arch::asm!(
            "svc #0x80",
            in("x16") num,
            inout("x0") a1 => ret,
            in("x1") a2,
            in("x2") a3,
            in("x3") a4,
            options(nostack),
        );
    }
    #[cfg(target_arch = "x86_64")]
    unsafe {
        core::arch::asm!(
            "syscall",
            inout("rax") num | 0x2000000 => ret,
            in("rdi") a1,
            in("rsi") a2,
            in("rdx") a3,
            in("r10") a4,
            out("rcx") _,
            out("r11") _,
            options(nostack),
        );
    }
    ret
}

/// Raw kernel syscall with 5 arguments.
#[inline(always)]
unsafe fn syscall5(num: i64, a1: u64, a2: u64, a3: u64, a4: u64, a5: u64) -> i64 {
    let ret: i64;
    #[cfg(target_arch = "aarch64")]
    unsafe {
        core::arch::asm!(
            "svc #0x80",
            in("x16") num,
            inout("x0") a1 => ret,
            in("x1") a2,
            in("x2") a3,
            in("x3") a4,
            in("x4") a5,
            options(nostack),
        );
    }
    #[cfg(target_arch = "x86_64")]
    unsafe {
        core::arch::asm!(
            "syscall",
            inout("rax") num | 0x2000000 => ret,
            in("rdi") a1,
            in("rsi") a2,
            in("rdx") a3,
            in("r10") a4,
            in("r8") a5,
            out("rcx") _,
            out("r11") _,
            options(nostack),
        );
    }
    ret
}

/// Raw kernel syscall with 6 arguments.
#[inline(always)]
unsafe fn syscall6(num: i64, a1: u64, a2: u64, a3: u64, a4: u64, a5: u64, a6: u64) -> i64 {
    let ret: i64;
    #[cfg(target_arch = "aarch64")]
    unsafe {
        core::arch::asm!(
            "svc #0x80",
            in("x16") num,
            inout("x0") a1 => ret,
            in("x1") a2,
            in("x2") a3,
            in("x3") a4,
            in("x4") a5,
            in("x5") a6,
            options(nostack),
        );
    }
    #[cfg(target_arch = "x86_64")]
    unsafe {
        core::arch::asm!(
            "syscall",
            inout("rax") num | 0x2000000 => ret,
            in("rdi") a1,
            in("rsi") a2,
            in("rdx") a3,
            in("r10") a4,
            in("r8") a5,
            in("r9") a6,
            out("rcx") _,
            out("r11") _,
            options(nostack),
        );
    }
    ret
}

/// Raw kernel syscall with 0 arguments.
#[inline(always)]
unsafe fn syscall0(num: i64) -> i64 {
    let ret: i64;
    #[cfg(target_arch = "aarch64")]
    unsafe {
        core::arch::asm!(
            "svc #0x80",
            in("x16") num,
            out("x0") ret,
            options(nostack),
        );
    }
    #[cfg(target_arch = "x86_64")]
    unsafe {
        core::arch::asm!(
            "syscall",
            inout("rax") num | 0x2000000 => ret,
            out("rdi") _,
            out("rcx") _,
            out("r11") _,
            options(nostack),
        );
    }
    ret
}

/// Raw kernel syscall with 8 arguments (connectx).
#[inline(always)]
unsafe fn syscall8(
    num: i64,
    a1: u64, a2: u64, a3: u64, a4: u64,
    a5: u64, a6: u64, a7: u64, a8: u64,
) -> i64 {
    // connectx has 8 args. On aarch64 XNU uses x0-x7. On x86_64, args 7-8
    // go on the stack. We fall back to libc::syscall for the 8-arg case on
    // x86_64 since inline asm stack args are fragile; aarch64 handles all 8
    // in registers.
    let ret: i64;
    #[cfg(target_arch = "aarch64")]
    unsafe {
        core::arch::asm!(
            "svc #0x80",
            in("x16") num,
            inout("x0") a1 => ret,
            in("x1") a2,
            in("x2") a3,
            in("x3") a4,
            in("x4") a5,
            in("x5") a6,
            in("x6") a7,
            in("x7") a8,
            options(nostack),
        );
    }
    #[cfg(target_arch = "x86_64")]
    {
        // x86_64 XNU syscall convention only has 6 register args (rdi, rsi,
        // rdx, r10, r8, r9). Args 7+ go on the stack via the C calling
        // convention. Using libc::syscall for this case is acceptable since
        // connectx is not on the hot path and libc::syscall with 8 args
        // handles the stack layout correctly.
        //
        // IMPORTANT: once T04 interposes libc::syscall, this fallback would
        // recurse. T04's syscall interpose must detect SYS_CONNECTX and
        // delegate here, and this function must use the real kernel entry.
        // For x86_64, we use a local assembly trampoline.
        core::arch::asm!(
            // Push args 7 and 8 onto the stack (reverse order for C ABI)
            "push {a8}",
            "push {a7}",
            "mov rax, {num}",
            "syscall",
            "add rsp, 16", // clean up the two pushed args
            num = in(reg) num | 0x2000000i64,
            in("rdi") a1,
            in("rsi") a2,
            in("rdx") a3,
            in("r10") a4,
            in("r8") a5,
            in("r9") a6,
            a7 = in(reg) a7,
            a8 = in(reg) a8,
            lateout("rax") ret,
            out("rcx") _,
            out("r11") _,
        );
    }
    ret
}

// ---- Public wrappers matching the signatures used by hook functions ----

#[inline(always)]
pub unsafe fn raw_connect(s: c_int, addr: *const sockaddr, addrlen: socklen_t) -> c_int {
    unsafe { syscall3(SYS_CONNECT, s as u64, addr as u64, addrlen as u64) as c_int }
}

#[inline(always)]
pub unsafe fn raw_connectx(
    s: c_int,
    endpoints: *const c_void,
    associd: c_int,
    flags: u32,
    iov: *const c_void,
    iovcnt: c_int,
    len: *mut size_t,
    connid: *mut c_int,
) -> c_int {
    unsafe {
        syscall8(
            SYS_CONNECTX,
            s as u64,
            endpoints as u64,
            associd as u64,
            flags as u64,
            iov as u64,
            iovcnt as u64,
            len as u64,
            connid as u64,
        ) as c_int
    }
}

#[inline(always)]
pub unsafe fn raw_sendto(
    s: c_int,
    buf: *const c_void,
    len: size_t,
    flags: c_int,
    to: *const sockaddr,
    tolen: socklen_t,
) -> ssize_t {
    unsafe {
        syscall6(
            SYS_SENDTO,
            s as u64,
            buf as u64,
            len as u64,
            flags as u64,
            to as u64,
            tolen as u64,
        ) as ssize_t
    }
}

#[inline(always)]
pub unsafe fn raw_sendmsg(s: c_int, msg: *const msghdr, flags: c_int) -> ssize_t {
    unsafe { syscall3(SYS_SENDMSG, s as u64, msg as u64, flags as u64) as ssize_t }
}

/// send() on macOS is sendto() with to=NULL, tolen=0.
#[inline(always)]
pub unsafe fn raw_send(s: c_int, buf: *const c_void, len: size_t, flags: c_int) -> ssize_t {
    unsafe {
        raw_sendto(
            s,
            buf,
            len,
            flags,
            core::ptr::null(),
            0,
        )
    }
}

#[inline(always)]
pub unsafe fn raw_read(fd: c_int, buf: *mut c_void, count: size_t) -> ssize_t {
    unsafe { syscall3(SYS_READ, fd as u64, buf as u64, count as u64) as ssize_t }
}

#[inline(always)]
pub unsafe fn raw_write(fd: c_int, buf: *const c_void, count: size_t) -> ssize_t {
    unsafe { syscall3(SYS_WRITE, fd as u64, buf as u64, count as u64) as ssize_t }
}

#[inline(always)]
pub unsafe fn raw_writev(fd: c_int, iov: *const libc::iovec, iovcnt: c_int) -> ssize_t {
    unsafe { syscall3(SYS_WRITEV, fd as u64, iov as u64, iovcnt as u64) as ssize_t }
}

#[inline(always)]
pub unsafe fn raw_fork() -> libc::pid_t {
    unsafe { syscall0(SYS_FORK) as libc::pid_t }
}

#[inline(always)]
pub unsafe fn raw_vfork() -> libc::pid_t {
    unsafe { syscall0(SYS_VFORK) as libc::pid_t }
}

#[inline(always)]
pub unsafe fn raw_getsockopt(
    s: c_int,
    level: c_int,
    optname: c_int,
    optval: *mut c_void,
    optlen: *mut socklen_t,
) -> c_int {
    unsafe {
        syscall5(
            SYS_GETSOCKOPT,
            s as u64,
            level as u64,
            optname as u64,
            optval as u64,
            optlen as u64,
        ) as c_int
    }
}

#[inline(always)]
pub unsafe fn raw_execve(
    path: *const core::ffi::c_char,
    argv: *const *const core::ffi::c_char,
    envp: *const *const core::ffi::c_char,
) -> c_int {
    unsafe { syscall3(SYS_EXECVE, path as u64, argv as u64, envp as u64) as c_int }
}

#[inline(always)]
pub unsafe fn raw_open(path: *const core::ffi::c_char, oflag: core::ffi::c_int, mode: libc::mode_t) -> core::ffi::c_int {
    unsafe { syscall3(SYS_OPEN, path as u64, oflag as u64, mode as u64) as core::ffi::c_int }
}

#[inline(always)]
pub unsafe fn raw_openat(
    dirfd: core::ffi::c_int,
    path: *const core::ffi::c_char,
    oflag: core::ffi::c_int,
    mode: libc::mode_t,
) -> core::ffi::c_int {
    unsafe { syscall4(SYS_OPENAT, dirfd as u64, path as u64, oflag as u64, mode as u64) as core::ffi::c_int }
}

/// Passthrough for arbitrary syscall numbers — used by the syscall()
/// interpose (T04) to forward non-network syscalls to the kernel.
#[inline(always)]
pub unsafe fn raw_syscall_passthrough(num: i64, a1: u64, a2: u64, a3: u64, a4: u64, a5: u64, a6: u64) -> i64 {
    unsafe { syscall6(num, a1, a2, a3, a4, a5, a6) }
}
