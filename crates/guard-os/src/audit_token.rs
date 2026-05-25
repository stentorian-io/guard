//! Process audit-token derivation.

use crate::OsError;
use guard_core::AuditToken;

#[cfg(target_os = "macos")]
mod imp {
    use super::*;

    type MachPortT = u32;
    type KernReturnT = i32;
    const MACH_PORT_NULL: MachPortT = 0;
    const KERN_SUCCESS: KernReturnT = 0;
    const TASK_AUDIT_TOKEN: u32 = 15;

    unsafe extern "C" {
        fn mach_task_self() -> MachPortT;
        fn task_name_for_pid(
            target_tport: MachPortT,
            pid: libc::pid_t,
            t: *mut MachPortT,
        ) -> KernReturnT;
        fn task_info(
            target_task: MachPortT,
            flavor: u32,
            task_info_out: *mut u32,
            task_info_count: *mut u32,
        ) -> KernReturnT;
        fn mach_port_deallocate(task: MachPortT, name: MachPortT) -> KernReturnT;
    }

    pub fn audit_token_for_pid(pid: libc::pid_t) -> Result<AuditToken, OsError> {
        let mut task_port: MachPortT = MACH_PORT_NULL;
        let kr = unsafe { task_name_for_pid(mach_task_self(), pid, &mut task_port) };
        if kr == KERN_SUCCESS {
            let mut token = AuditToken::synthetic([0u32; 8]);
            let mut count: u32 = 8;
            let kr2 = unsafe {
                task_info(
                    task_port,
                    TASK_AUDIT_TOKEN,
                    token.val.as_mut_ptr(),
                    &mut count,
                )
            };
            unsafe { mach_port_deallocate(mach_task_self(), task_port) };
            if kr2 == KERN_SUCCESS {
                return Ok(token);
            }
        }

        audit_token_for_pid_fallback(pid)
    }

    fn audit_token_for_pid_fallback(pid: libc::pid_t) -> Result<AuditToken, OsError> {
        use std::mem::MaybeUninit;

        const PROC_PIDTBSDINFO: i32 = 3;
        const PROC_PIDTBSDINFO_SIZE: i32 = 136;

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
            return Err(OsError::unexpected_data(
                "process audit token",
                format!(
                    "proc_pidinfo(PROC_PIDTBSDINFO, pid={pid}) returned {n}, expected {PROC_PIDTBSDINFO_SIZE}"
                ),
            ));
        }
        let info = unsafe { info.assume_init() };
        let pidversion_analog: u32 = (info.pbi_start_tvsec as u32) ^ (info.pbi_start_tvusec as u32);
        let mut val = [0u32; 8];
        val[1] = info.pbi_uid;
        val[2] = info.pbi_gid;
        val[5] = pid as u32;
        val[7] = pidversion_analog;
        Ok(AuditToken::synthetic(val))
    }
}

#[cfg(not(target_os = "macos"))]
mod imp {
    use super::*;

    #[cfg(target_os = "linux")]
    pub fn audit_token_for_pid(pid: libc::pid_t) -> Result<AuditToken, OsError> {
        if pid <= 0 {
            return Err(OsError::unexpected_data(
                "process audit token",
                format!("invalid pid {pid}"),
            ));
        }

        let uid = crate::process::process_uid(pid)?;
        let gid = crate::process::process_gid(pid)?;
        let starttime = crate::process::process_starttime_ticks(pid)?;
        let pidversion = crate::process::starttime_ticks_to_pidversion(starttime);

        let mut val = [0u32; 8];
        val[1] = uid;
        val[2] = gid;
        val[3] = uid;
        val[4] = gid;
        val[5] = pid as u32;
        val[7] = pidversion;
        Ok(AuditToken::synthetic(val))
    }

    #[cfg(not(target_os = "linux"))]
    pub fn audit_token_for_pid(_pid: libc::pid_t) -> Result<AuditToken, OsError> {
        Err(OsError::unsupported("process audit token"))
    }
}

/// Return a best-effort audit token for a process.
///
/// On macOS this uses `task_name_for_pid` + `task_info(TASK_AUDIT_TOKEN)`,
/// with a `proc_pidinfo(PROC_PIDTBSDINFO)` fallback for tracked pid and
/// pidversion context. Linux returns a synthetic token using procfs uid/gid,
/// pid, and starttime-derived pidversion context. Other platforms report the
/// capability as unsupported.
pub fn audit_token_for_pid(pid: libc::pid_t) -> Result<AuditToken, OsError> {
    imp::audit_token_for_pid(pid)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[cfg(target_os = "macos")]
    fn audit_token_for_self_pid_succeeds() {
        let pid = unsafe { libc::getpid() };
        let token = audit_token_for_pid(pid).expect("audit_token_for_pid");
        assert_eq!(token.val[5] as libc::pid_t, pid);
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn audit_token_for_self_pid_succeeds_on_linux() {
        let pid = unsafe { libc::getpid() };
        let token = audit_token_for_pid(pid).expect("audit_token_for_pid");
        assert_eq!(token.val[5] as libc::pid_t, pid);
        assert_ne!(token.val[7], 0, "linux starttime pidversion should be set");
    }

    #[test]
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    fn audit_token_for_pid_is_explicitly_unsupported() {
        let err = audit_token_for_pid(1).expect_err("non-macOS audit token");
        assert!(matches!(
            err,
            OsError::Unsupported {
                capability: "process audit token",
                ..
            }
        ));
    }
}
