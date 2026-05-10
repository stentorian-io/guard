//! Interpose for libc syscall() — catches bypass attempts where malicious
//! code calls `syscall(SYS_CONNECT, ...)` directly instead of `connect()`.
//!
//! Network-relevant syscall numbers are intercepted and routed through
//! policy evaluation. All other syscalls pass through to the kernel via
//! raw inline assembly (never through libc::syscall, which would recurse).

use crate::log_buffer::LOG_RING;
use crate::raw_syscall;
use crate::reentrancy::IN_HOOK;
use crate::replace_libc::_decide_for_sockaddr_pub;
use core::ffi::{c_int, c_void};
use libc::{sockaddr, socklen_t};
use sentinel_core::Verdict;

struct InHookGuard {
    _priv: (),
}
impl InHookGuard {
    #[inline]
    fn enter() -> Option<Self> {
        if IN_HOOK.with(|c| c.replace(true)) {
            None
        } else {
            Some(Self { _priv: () })
        }
    }
}
impl Drop for InHookGuard {
    #[inline]
    fn drop(&mut self) {
        IN_HOOK.with(|c| c.set(false));
    }
}

// macOS BSD syscall numbers for network calls we intercept.
const SYS_CONNECT: i64 = 98;
const SYS_CONNECTX: i64 = 447;
const SYS_SENDTO: i64 = 133;
const SYS_SENDMSG: i64 = 28;

/// Interpose for libc `syscall(int number, ...)`.
///
/// On macOS, libc's `syscall()` is a variadic C function. We declare a
/// non-variadic 7-arg signature that covers syscalls with up to 6 args
/// (which is the maximum for register-passed args on both aarch64 and
/// x86_64). The extra args are harmless for syscalls that use fewer.
///
/// For network-related syscall numbers, we extract the args and route
/// through our policy evaluation. Everything else passes straight through
/// to the kernel via raw assembly.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sentinel_syscall(
    number: c_int,
    a1: u64,
    a2: u64,
    a3: u64,
    a4: u64,
    a5: u64,
    a6: u64,
) -> i64 {
    let num = number as i64;

    // Fast path: non-network syscalls pass through immediately.
    if num != SYS_CONNECT && num != SYS_CONNECTX && num != SYS_SENDTO && num != SYS_SENDMSG {
        return unsafe { raw_syscall::raw_syscall_passthrough(num, a1, a2, a3, a4, a5, a6) };
    }

    // Reentrancy guard — if already in a hook, pass through.
    let _guard = match InHookGuard::enter() {
        Some(g) => g,
        None => return unsafe { raw_syscall::raw_syscall_passthrough(num, a1, a2, a3, a4, a5, a6) },
    };

    match num {
        SYS_CONNECT => {
            // syscall(SYS_CONNECT, fd, addr, addrlen)
            let addr = a2 as *const sockaddr;
            let addrlen = a3 as socklen_t;
            let verdict = unsafe { _decide_for_sockaddr_pub(addr, addrlen) };
            if matches!(verdict, Verdict::Deny) {
                unsafe { *libc::__error() = libc::EHOSTUNREACH; }
                LOG_RING.append(b"[sentinel-hook] DENY syscall(SYS_CONNECT)");
                return -1;
            }
            unsafe { raw_syscall::raw_connect(a1 as c_int, addr, addrlen) as i64 }
        }
        SYS_CONNECTX => {
            // syscall(SYS_CONNECTX, fd, endpoints, associd, flags, iov, iovcnt, len, connid)
            // connectx has 8 args — a7 and a8 would be on the stack in the
            // variadic call. Our 7-arg signature captures up to a6 (iovcnt).
            // len and connid (args 7-8) are not captured here. Since
            // connectx policy is based on the endpoints (a2), we can evaluate
            // the policy and then pass through to the real syscall.
            let endpoints = a2 as *const c_void;
            if endpoints.is_null() {
                unsafe { *libc::__error() = libc::EHOSTUNREACH; }
                LOG_RING.append(b"[sentinel-hook] DENY syscall(SYS_CONNECTX) null endpoints");
                return -1;
            }
            let ep = unsafe { &*(endpoints as *const crate::replace_libc::SaEndpoints) };
            let verdict = unsafe { _decide_for_sockaddr_pub(ep.sae_dstaddr, ep.sae_dstaddrlen) };
            if matches!(verdict, Verdict::Deny) {
                unsafe { *libc::__error() = libc::EHOSTUNREACH; }
                LOG_RING.append(b"[sentinel-hook] DENY syscall(SYS_CONNECTX)");
                return -1;
            }
            // Pass through all args — use raw_syscall_passthrough for 6 args,
            // which is sufficient for the register-passed args.
            unsafe { raw_syscall::raw_syscall_passthrough(num, a1, a2, a3, a4, a5, a6) }
        }
        SYS_SENDTO => {
            // syscall(SYS_SENDTO, fd, buf, len, flags, to, tolen)
            let to = a5 as *const sockaddr;
            let tolen = a6 as socklen_t;
            if to.is_null() || tolen == 0 {
                // Connected socket send — destination already permitted.
                return unsafe { raw_syscall::raw_syscall_passthrough(num, a1, a2, a3, a4, a5, a6) };
            }
            let verdict = unsafe { _decide_for_sockaddr_pub(to, tolen) };
            if matches!(verdict, Verdict::Deny) {
                unsafe { *libc::__error() = libc::EHOSTUNREACH; }
                LOG_RING.append(b"[sentinel-hook] DENY syscall(SYS_SENDTO)");
                return -1;
            }
            unsafe { raw_syscall::raw_syscall_passthrough(num, a1, a2, a3, a4, a5, a6) }
        }
        SYS_SENDMSG => {
            // syscall(SYS_SENDMSG, fd, msg, flags)
            let msg = a2 as *const libc::msghdr;
            if msg.is_null() {
                unsafe { *libc::__error() = libc::EHOSTUNREACH; }
                LOG_RING.append(b"[sentinel-hook] DENY syscall(SYS_SENDMSG) null msg");
                return -1;
            }
            let m = unsafe { &*msg };
            if m.msg_name.is_null() || m.msg_namelen == 0 {
                // Connected socket send — pass through.
                return unsafe { raw_syscall::raw_syscall_passthrough(num, a1, a2, a3, a4, a5, a6) };
            }
            let verdict = unsafe { _decide_for_sockaddr_pub(m.msg_name as *const sockaddr, m.msg_namelen) };
            if matches!(verdict, Verdict::Deny) {
                unsafe { *libc::__error() = libc::EHOSTUNREACH; }
                LOG_RING.append(b"[sentinel-hook] DENY syscall(SYS_SENDMSG)");
                return -1;
            }
            unsafe { raw_syscall::raw_syscall_passthrough(num, a1, a2, a3, a4, a5, a6) }
        }
        _ => unreachable!(),
    }
}
