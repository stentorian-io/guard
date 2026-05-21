//! Derive an AuditToken for a given pid using Mach task_name_for_pid +
//! task_info(TASK_AUDIT_TOKEN). Hand-rolled FFI per RESEARCH.md.

use guard_core::AuditToken;

// Mach types (kept private — we only export AuditToken).
type MachPortT = u32;
type KernReturnT = i32;
const MACH_PORT_NULL: MachPortT = 0;
const KERN_SUCCESS: KernReturnT = 0;

// TASK_AUDIT_TOKEN flavor — from <mach/task_info.h>
const TASK_AUDIT_TOKEN: u32 = 15;

unsafe extern "C" {
    /// Apple's mach_task_self() — returns our own task port.
    fn mach_task_self() -> MachPortT;

    /// Apple's task_name_for_pid — gives us a name port (read-only) for the target task.
    fn task_name_for_pid(
        target_tport: MachPortT,
        pid: libc::pid_t,
        t: *mut MachPortT,
    ) -> KernReturnT;

    /// Apple's task_info — used with TASK_AUDIT_TOKEN flavor (15) to retrieve the task's audit token.
    fn task_info(
        target_task: MachPortT,
        flavor: u32,
        task_info_out: *mut u32, // pointer to AuditToken's val[8]
        task_info_count: *mut u32,
    ) -> KernReturnT;

    /// Apple's mach_port_deallocate — releases a send-right back to the kernel.
    ///
    /// BL-02 fix: task_name_for_pid returns a Mach send-right that MUST be
    /// deallocated on every return path. Failure to do so leaks a port reference
    /// per call, and per-task port limits (default ~16,384 send-rights) eventually
    /// cause task_name_for_pid to fail or the task to be terminated.
    fn mach_port_deallocate(task: MachPortT, name: MachPortT) -> KernReturnT;
}

pub fn audit_token_for_pid(pid: libc::pid_t) -> std::io::Result<AuditToken> {
    // Primary path: task_name_for_pid + task_info(TASK_AUDIT_TOKEN). Apple has
    // been tightening task-port access on recent macOS releases — same-UID
    // callers are still permitted today (macOS 14+), but to make this code
    // robust against future tightening we have a proc_pidinfo fallback below.
    let mut task_port: MachPortT = MACH_PORT_NULL;
    let kr = unsafe { task_name_for_pid(mach_task_self(), pid, &mut task_port) };
    if kr == KERN_SUCCESS {
        let mut token = AuditToken::synthetic([0u32; 8]);
        let mut count: u32 = 8; // 8 × u32
        let kr2 = unsafe {
            task_info(
                task_port,
                TASK_AUDIT_TOKEN,
                token.val.as_mut_ptr(),
                &mut count,
            )
        };
        // BL-02 fix: always deallocate the Mach send-right returned by
        // task_name_for_pid, regardless of whether task_info succeeded or
        // failed. Without this, every successful call leaks one Mach port
        // reference. Per-task port limits (~16,384 send-rights by default)
        // will eventually cause task_name_for_pid to fail or the task to be
        // terminated in a long-running process.
        unsafe { mach_port_deallocate(mach_task_self(), task_port) };
        if kr2 == KERN_SUCCESS {
            return Ok(token);
        }
        // task_info failure on a successful task_name_for_pid is unusual — log
        // and fall through to the proc_pidinfo fallback path.
        tracing::warn!(
            pid,
            kr = kr2,
            "task_info(TASK_AUDIT_TOKEN) failed, using proc_pidinfo fallback"
        );
    } else {
        tracing::warn!(
            pid,
            kr,
            "task_name_for_pid failed, using proc_pidinfo fallback"
        );
    }

    // ISS-10 fallback: proc_pidinfo(PROC_PIDTBSDINFO) is freely available to
    // same-UID callers without entitlement. We retrieve (pid, p_starttime) and
    // use p_starttime as a pidversion analog for the wire payload. The daemon
    // is the trust anchor for audit-token validity (it derives the
    // authoritative AuditToken from LOCAL_PEERTOKEN per plan 05); the wire
    // payload is best-effort context for the daemon's tracked-roots map.
    audit_token_for_pid_fallback(pid)
}

/// proc_pidinfo(PROC_PIDTBSDINFO) fallback. Returns a synthetic AuditToken
/// with val[5] = pid and val[7] = (p_starttime_sec ^ p_starttime_usec) as a
/// pidversion analog. The daemon's LOCAL_PEERTOKEN-derived AuditToken
/// remains the authoritative trust anchor (per plan 05 + T-01-04-03).
fn audit_token_for_pid_fallback(pid: libc::pid_t) -> std::io::Result<AuditToken> {
    use std::mem::MaybeUninit;
    const PROC_PIDTBSDINFO: i32 = 3;
    const PROC_PIDTBSDINFO_SIZE: i32 = 136; // sizeof(struct proc_bsdinfo) on Darwin (arm64 / x86_64)

    // Minimal layout of proc_bsdinfo — only the fields we use.
    // Full struct is 232 bytes on Darwin; we only read offsets we care about.
    #[repr(C)]
    struct ProcBsdInfo {
        pbi_flags: u32,
        pbi_status: u32,
        pbi_xstatus: u32,
        pbi_pid: u32,
        pbi_ppid: u32,
        pbi_uid: u32,
        pbi_gid: u32,
        pbi_ruid: u32,
        pbi_rgid: u32,
        pbi_svuid: u32,
        pbi_svgid: u32,
        rfu_1: u32,
        pbi_comm: [u8; 16],
        pbi_name: [u8; 32],
        pbi_nfiles: u32,
        pbi_pgid: u32,
        pbi_pjobc: u32,
        e_tdev: u32,
        e_tpgid: u32,
        pbi_nice: i32,
        pbi_start_tvsec: u64,
        pbi_start_tvusec: u64,
    }

    // Static assertion: verify our struct layout matches the Darwin size.
    const _: () = assert!(
        std::mem::size_of::<ProcBsdInfo>() == PROC_PIDTBSDINFO_SIZE as usize,
        "ProcBsdInfo layout mismatch with Darwin proc_bsdinfo"
    );

    unsafe extern "C" {
        fn proc_pidinfo(
            pid: libc::c_int,
            flavor: libc::c_int,
            arg: u64,
            buffer: *mut libc::c_void,
            buffersize: libc::c_int,
        ) -> libc::c_int;
    }

    let mut info: MaybeUninit<ProcBsdInfo> = MaybeUninit::uninit();
    let n = unsafe {
        proc_pidinfo(
            pid,
            PROC_PIDTBSDINFO,
            0,
            info.as_mut_ptr() as *mut libc::c_void,
            PROC_PIDTBSDINFO_SIZE,
        )
    };
    if n != PROC_PIDTBSDINFO_SIZE {
        return Err(std::io::Error::other(format!(
            "proc_pidinfo(PROC_PIDTBSDINFO, pid={pid}) returned {n}, expected {PROC_PIDTBSDINFO_SIZE}"
        )));
    }
    let info = unsafe { info.assume_init() };
    let pidversion_analog: u32 = (info.pbi_start_tvsec as u32) ^ (info.pbi_start_tvusec as u32);
    // val[5] = pid, val[7] = pidversion analog; other fields zero.
    // Daemon's LOCAL_PEERTOKEN-derived AuditToken is the trust anchor.
    let mut val = [0u32; 8];
    val[1] = info.pbi_uid;
    val[2] = info.pbi_gid;
    val[5] = pid as u32;
    val[7] = pidversion_analog;
    Ok(AuditToken::synthetic(val))
}
