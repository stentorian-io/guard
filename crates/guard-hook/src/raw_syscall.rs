//! Direct kernel syscall wrappers using inline assembly.
//!
//! These bypass `libc::syscall()` entirely. The active hooks use them for
//! allowed call-through so dyld interposition never resolves a "real" libc
//! symbol back to Stentorian Guard's replacement function.
//!
//! macOS/XNU syscall ABI:
//! - aarch64: x16 = syscall number, x0-x5 = args, svc #0x80, result in x0
//! - `x86_64`:  rax = syscall number | 0x2000000, rdi/rsi/rdx/r10/r8/r9 = args,
//!   syscall instruction, result in rax
//!
//! The 0x2000000 prefix on `x86_64` selects the BSD syscall class on XNU.

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

fn c_int_arg(value: c_int) -> u64 {
    u64::from_ne_bytes(i64::from(value).to_ne_bytes())
}

fn ptr_arg<T>(ptr: *const T) -> u64 {
    u64::try_from(ptr.addr()).unwrap_or(u64::MAX)
}

fn mut_ptr_arg<T>(ptr: *mut T) -> u64 {
    u64::try_from(ptr.addr()).unwrap_or(u64::MAX)
}

fn size_arg(value: size_t) -> u64 {
    u64::try_from(value).unwrap_or(u64::MAX)
}

fn syscall_ret_c_int(value: i64) -> c_int {
    c_int::try_from(value).unwrap_or(if value < 0 { -1 } else { c_int::MAX })
}

fn syscall_ret_ssize(value: i64) -> ssize_t {
    ssize_t::try_from(value).unwrap_or(if value < 0 { -1 } else { ssize_t::MAX })
}

/// Raw kernel syscall with 3 arguments.
#[inline]
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
            inout("rax") num | 0x0200_0000 => ret,
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
#[inline]
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
            inout("rax") num | 0x0200_0000 => ret,
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
#[inline]
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
            inout("rax") num | 0x0200_0000 => ret,
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
#[inline]
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
            inout("rax") num | 0x0200_0000 => ret,
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
#[inline]
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
            inout("rax") num | 0x0200_0000 => ret,
            out("rdi") _,
            out("rcx") _,
            out("r11") _,
            options(nostack),
        );
    }
    ret
}

/// Raw kernel syscall with 8 arguments (connectx).
#[inline]
unsafe fn syscall8(num: i64, args: [u64; 8]) -> i64 {
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
            inout("x0") args[0] => ret,
            in("x1") args[1],
            in("x2") args[2],
            in("x3") args[3],
            in("x4") args[4],
            in("x5") args[5],
            in("x6") args[6],
            in("x7") args[7],
            options(nostack),
        );
    }
    #[cfg(target_arch = "x86_64")]
    unsafe {
        // x86_64 XNU syscall convention only has 6 register args (rdi, rsi,
        // rdx, r10, r8, r9). Args 7+ go on the stack via the C calling
        // convention, so use a local assembly trampoline instead of
        // libc::syscall.
        core::arch::asm!(
            // Push args 7 and 8 onto the stack (reverse order for C ABI)
            "push {arg8}",
            "push {arg7}",
            "mov rax, {num}",
            "syscall",
            "add rsp, 16", // clean up the two pushed args
            num = in(reg) num | 0x0200_0000_i64,
            in("rdi") args[0],
            in("rsi") args[1],
            in("rdx") args[2],
            in("r10") args[3],
            in("r8") args[4],
            in("r9") args[5],
            arg7 = in(reg) args[6],
            arg8 = in(reg) args[7],
            lateout("rax") ret,
            out("rcx") _,
            out("r11") _,
        );
    }
    ret
}

// ---- Public wrappers matching the signatures used by hook functions ----

pub struct ConnectxArgs {
    pub socket: c_int,
    pub endpoints: *const c_void,
    pub associd: c_int,
    pub flags: u32,
    pub iov: *const c_void,
    pub iovcnt: c_int,
    pub len: *mut size_t,
    pub connid: *mut c_int,
}

#[inline]
#[must_use]
/// Invoke the kernel `connect(2)` syscall without going through interposed libc.
///
/// # Safety
///
/// `addr` and `addrlen` must satisfy the platform `connect(2)` contract.
pub unsafe fn raw_connect(s: c_int, addr: *const sockaddr, addrlen: socklen_t) -> c_int {
    let result = unsafe { syscall3(SYS_CONNECT, c_int_arg(s), ptr_arg(addr), u64::from(addrlen)) };

    syscall_ret_c_int(result)
}

#[inline]
/// Invoke the kernel `connectx(2)` syscall without going through interposed libc.
///
/// # Safety
///
/// All pointer/count pairs must satisfy the platform `connectx(2)` contract.
#[must_use]
pub unsafe fn raw_connectx(args: &ConnectxArgs) -> c_int {
    let result = unsafe {
        syscall8(
            SYS_CONNECTX,
            [
                c_int_arg(args.socket),
                ptr_arg(args.endpoints),
                c_int_arg(args.associd),
                u64::from(args.flags),
                ptr_arg(args.iov),
                c_int_arg(args.iovcnt),
                mut_ptr_arg(args.len),
                mut_ptr_arg(args.connid),
            ],
        )
    };

    syscall_ret_c_int(result)
}

#[inline]
#[must_use]
/// Invoke the kernel `sendto(2)` syscall without going through interposed libc.
///
/// # Safety
///
/// `buf`, `len`, `to`, and `tolen` must satisfy the platform `sendto(2)`
/// contract.
pub unsafe fn raw_sendto(
    s: c_int,
    buf: *const c_void,
    len: size_t,
    flags: c_int,
    to: *const sockaddr,
    tolen: socklen_t,
) -> ssize_t {
    let result = unsafe {
        syscall6(
            SYS_SENDTO,
            c_int_arg(s),
            ptr_arg(buf),
            size_arg(len),
            c_int_arg(flags),
            ptr_arg(to),
            u64::from(tolen),
        )
    };

    syscall_ret_ssize(result)
}

#[inline]
#[must_use]
/// Invoke the kernel `sendmsg(2)` syscall without going through interposed libc.
///
/// # Safety
///
/// `msg` must satisfy the platform `sendmsg(2)` contract.
pub unsafe fn raw_sendmsg(s: c_int, msg: *const msghdr, flags: c_int) -> ssize_t {
    let result = unsafe { syscall3(SYS_SENDMSG, c_int_arg(s), ptr_arg(msg), c_int_arg(flags)) };

    syscall_ret_ssize(result)
}

/// `send()` on macOS is `sendto()` with to=NULL, tolen=0.
#[inline]
#[must_use]
/// Invoke the kernel `send(2)` syscall without going through interposed libc.
///
/// # Safety
///
/// `buf` and `len` must satisfy the platform `send(2)` contract.
pub unsafe fn raw_send(s: c_int, buf: *const c_void, len: size_t, flags: c_int) -> ssize_t {
    unsafe { raw_sendto(s, buf, len, flags, core::ptr::null(), 0) }
}

#[inline]
/// Invoke the kernel `read(2)` syscall without going through interposed libc.
///
/// # Safety
///
/// `buf` and `count` must satisfy the platform `read(2)` contract.
pub unsafe fn raw_read(fd: c_int, buf: *mut c_void, count: size_t) -> ssize_t {
    let result = unsafe { syscall3(SYS_READ, c_int_arg(fd), mut_ptr_arg(buf), size_arg(count)) };

    syscall_ret_ssize(result)
}

#[inline]
#[must_use]
/// Invoke the kernel `write(2)` syscall without going through interposed libc.
///
/// # Safety
///
/// `buf` and `count` must satisfy the platform `write(2)` contract.
pub unsafe fn raw_write(fd: c_int, buf: *const c_void, count: size_t) -> ssize_t {
    let result = unsafe { syscall3(SYS_WRITE, c_int_arg(fd), ptr_arg(buf), size_arg(count)) };

    syscall_ret_ssize(result)
}

#[inline]
#[must_use]
/// Invoke the kernel `writev(2)` syscall without going through interposed libc.
///
/// # Safety
///
/// `iov` and `iovcnt` must satisfy the platform `writev(2)` contract.
pub unsafe fn raw_writev(fd: c_int, iov: *const libc::iovec, iovcnt: c_int) -> ssize_t {
    let result = unsafe { syscall3(SYS_WRITEV, c_int_arg(fd), ptr_arg(iov), c_int_arg(iovcnt)) };

    syscall_ret_ssize(result)
}

#[inline]
#[must_use]
/// Invoke the kernel `fork(2)` syscall without going through interposed libc.
///
/// # Safety
///
/// The caller must only run async-signal-safe operations in the child before
/// exec or exit.
pub unsafe fn raw_fork() -> libc::pid_t {
    syscall_ret_c_int(unsafe { syscall0(SYS_FORK) })
}

#[inline]
#[must_use]
/// Invoke the kernel `vfork(2)` syscall without going through interposed libc.
///
/// # Safety
///
/// The caller must preserve the `vfork(2)` contract: the child may not mutate
/// parent-owned state before exec or exit.
pub unsafe fn raw_vfork() -> libc::pid_t {
    syscall_ret_c_int(unsafe { syscall0(SYS_VFORK) })
}

#[inline]
/// Invoke the kernel `getsockopt(2)` syscall without going through interposed libc.
///
/// # Safety
///
/// `optval` and `optlen` must satisfy the platform `getsockopt(2)` contract.
pub unsafe fn raw_getsockopt(
    s: c_int,
    level: c_int,
    optname: c_int,
    optval: *mut c_void,
    optlen: *mut socklen_t,
) -> c_int {
    let result = unsafe {
        syscall5(
            SYS_GETSOCKOPT,
            c_int_arg(s),
            c_int_arg(level),
            c_int_arg(optname),
            mut_ptr_arg(optval),
            mut_ptr_arg(optlen),
        )
    };

    syscall_ret_c_int(result)
}

#[inline]
#[must_use]
/// Invoke the kernel `execve(2)` syscall without going through interposed libc.
///
/// # Safety
///
/// `path`, `argv`, and `envp` must satisfy the platform `execve(2)` contract.
pub unsafe fn raw_execve(
    path: *const core::ffi::c_char,
    argv: *const *const core::ffi::c_char,
    envp: *const *const core::ffi::c_char,
) -> c_int {
    let result = unsafe { syscall3(SYS_EXECVE, ptr_arg(path), ptr_arg(argv), ptr_arg(envp)) };

    syscall_ret_c_int(result)
}

#[inline]
#[must_use]
/// Invoke the kernel `open(2)` syscall without going through interposed libc.
///
/// # Safety
///
/// `path` must satisfy the platform `open(2)` contract.
pub unsafe fn raw_open(
    path: *const core::ffi::c_char,
    oflag: core::ffi::c_int,
    mode: libc::mode_t,
) -> core::ffi::c_int {
    let result = unsafe { syscall3(SYS_OPEN, ptr_arg(path), c_int_arg(oflag), u64::from(mode)) };

    syscall_ret_c_int(result)
}

#[inline]
#[must_use]
/// Invoke the kernel `openat(2)` syscall without going through interposed libc.
///
/// # Safety
///
/// `path` must satisfy the platform `openat(2)` contract.
pub unsafe fn raw_openat(
    dirfd: core::ffi::c_int,
    path: *const core::ffi::c_char,
    oflag: core::ffi::c_int,
    mode: libc::mode_t,
) -> core::ffi::c_int {
    let result = unsafe {
        syscall4(
            SYS_OPENAT,
            c_int_arg(dirfd),
            ptr_arg(path),
            c_int_arg(oflag),
            u64::from(mode),
        )
    };

    syscall_ret_c_int(result)
}
