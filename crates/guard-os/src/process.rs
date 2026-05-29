//! Process inspection primitives.

use crate::OsError;

#[cfg(target_os = "macos")]
mod imp {
    use super::OsError;

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

    pub fn kernel_pidversion(pid: libc::pid_t) -> Option<u32> {
        unsafe {
            let mut task_port: MachPortT = MACH_PORT_NULL;
            let kr = task_name_for_pid(mach_task_self(), pid, &raw mut task_port);
            if kr != KERN_SUCCESS {
                return None;
            }
            let mut token_val = [0u32; 8];
            let mut count: u32 = 8;
            let kr2 = task_info(
                task_port,
                TASK_AUDIT_TOKEN,
                token_val.as_mut_ptr(),
                &raw mut count,
            );
            mach_port_deallocate(mach_task_self(), task_port);
            if kr2 != KERN_SUCCESS {
                return None;
            }
            Some(token_val[7])
        }
    }

    pub fn process_uid(pid: libc::pid_t) -> Result<u32, OsError> {
        unsafe {
            let mut info: libc::proc_bsdinfo = std::mem::zeroed();
            let info_size = libc::c_int::try_from(std::mem::size_of::<libc::proc_bsdinfo>())
                .expect("proc_bsdinfo size fits c_int");
            let n = libc::proc_pidinfo(
                pid,
                libc::PROC_PIDTBSDINFO,
                0,
                (&raw mut info).cast::<libc::c_void>(),
                info_size,
            );
            if n != info_size {
                return Err(OsError::unexpected_data(
                    "process uid",
                    format!("proc_pidinfo returned {n}, expected {info_size}"),
                ));
            }
            Ok(info.pbi_uid)
        }
    }

    pub fn process_gid(pid: libc::pid_t) -> Result<u32, OsError> {
        unsafe {
            let mut info: libc::proc_bsdinfo = std::mem::zeroed();
            let info_size = libc::c_int::try_from(std::mem::size_of::<libc::proc_bsdinfo>())
                .expect("proc_bsdinfo size fits c_int");
            let n = libc::proc_pidinfo(
                pid,
                libc::PROC_PIDTBSDINFO,
                0,
                (&raw mut info).cast::<libc::c_void>(),
                info_size,
            );
            if n != info_size {
                return Err(OsError::unexpected_data(
                    "process gid",
                    format!("proc_pidinfo returned {n}, expected {info_size}"),
                ));
            }
            Ok(info.pbi_gid)
        }
    }

    pub fn process_path(pid: libc::pid_t) -> Option<String> {
        let mut buf = [0u8; libc::MAXPATHLEN as usize];
        let buf_len = u32::try_from(buf.len()).expect("MAXPATHLEN fits u32");
        let n =
            unsafe { libc::proc_pidpath(pid, buf.as_mut_ptr().cast::<libc::c_void>(), buf_len) };
        if n > 0 {
            let path_len = usize::try_from(n).expect("positive proc_pidpath length fits usize");
            Some(String::from_utf8_lossy(&buf[..path_len]).to_string())
        } else {
            None
        }
    }
}

#[cfg(not(target_os = "macos"))]
mod imp {
    use super::OsError;

    #[cfg(target_os = "linux")]
    pub fn kernel_pidversion(pid: libc::pid_t) -> Option<u32> {
        process_starttime_ticks(pid)
            .ok()
            .map(starttime_ticks_to_pidversion)
    }

    #[cfg(not(target_os = "linux"))]
    pub fn kernel_pidversion(_pid: libc::pid_t) -> Option<u32> {
        None
    }

    #[cfg(target_os = "linux")]
    pub fn process_uid(pid: libc::pid_t) -> Result<u32, OsError> {
        process_status_ids(pid).map(|ids| ids.uid)
    }

    #[cfg(not(target_os = "linux"))]
    pub fn process_uid(_pid: libc::pid_t) -> Result<u32, OsError> {
        Err(OsError::unsupported("process uid"))
    }

    #[cfg(target_os = "linux")]
    pub fn process_gid(pid: libc::pid_t) -> Result<u32, OsError> {
        process_status_ids(pid).map(|ids| ids.gid)
    }

    #[cfg(not(target_os = "linux"))]
    pub fn process_gid(_pid: libc::pid_t) -> Result<u32, OsError> {
        Err(OsError::unsupported("process gid"))
    }

    #[cfg(target_os = "linux")]
    pub fn process_path(pid: libc::pid_t) -> Option<String> {
        std::fs::read_link(format!("/proc/{pid}/exe"))
            .ok()
            .map(|path| path.display().to_string())
    }

    #[cfg(not(target_os = "linux"))]
    pub fn process_path(_pid: libc::pid_t) -> Option<String> {
        None
    }

    #[cfg(target_os = "linux")]
    #[derive(Debug, Clone, Copy)]
    struct ProcessStatusIds {
        uid: u32,
        gid: u32,
    }

    #[cfg(target_os = "linux")]
    pub fn process_starttime_ticks(pid: libc::pid_t) -> Result<u64, OsError> {
        let stat = std::fs::read_to_string(format!("/proc/{pid}/stat"))
            .map_err(|e| OsError::io("process starttime", e))?;
        parse_proc_stat_starttime(&stat)
    }

    #[cfg(target_os = "linux")]
    pub fn starttime_ticks_to_pidversion(starttime_ticks: u64) -> u32 {
        let bytes = starttime_ticks.to_le_bytes();
        let low = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        let high = u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
        low ^ high
    }

    #[cfg(target_os = "linux")]
    fn process_status_ids(pid: libc::pid_t) -> Result<ProcessStatusIds, OsError> {
        let status = std::fs::read_to_string(format!("/proc/{pid}/status"))
            .map_err(|e| OsError::io("process status", e))?;
        parse_proc_status_ids(&status)
    }

    #[cfg(target_os = "linux")]
    fn parse_proc_status_ids(status: &str) -> Result<ProcessStatusIds, OsError> {
        let mut uid = None;
        let mut gid = None;

        for line in status.lines() {
            if let Some(rest) = line.strip_prefix("Uid:") {
                uid = Some(parse_first_status_id(rest, "process uid")?);
            } else if let Some(rest) = line.strip_prefix("Gid:") {
                gid = Some(parse_first_status_id(rest, "process gid")?);
            }
        }

        match (uid, gid) {
            (Some(uid), Some(gid)) => Ok(ProcessStatusIds { uid, gid }),
            _ => Err(OsError::unexpected_data(
                "process status",
                "missing Uid or Gid line",
            )),
        }
    }

    #[cfg(target_os = "linux")]
    fn parse_first_status_id(rest: &str, capability: &'static str) -> Result<u32, OsError> {
        let first = rest.split_whitespace().next().ok_or_else(|| {
            OsError::unexpected_data(capability, "status id line has no numeric fields")
        })?;
        first
            .parse()
            .map_err(|e| OsError::unexpected_data(capability, format!("invalid id {first}: {e}")))
    }

    #[cfg(target_os = "linux")]
    fn parse_proc_stat_starttime(stat: &str) -> Result<u64, OsError> {
        let Some(comm_end) = stat.rfind(") ") else {
            return Err(OsError::unexpected_data(
                "process starttime",
                "missing comm terminator",
            ));
        };
        let mut fields_after_comm = stat[comm_end + 2..].split_whitespace();
        let Some(starttime) = fields_after_comm.nth(19) else {
            return Err(OsError::unexpected_data(
                "process starttime",
                "stat has fewer than 22 fields",
            ));
        };
        starttime.parse().map_err(|e| {
            OsError::unexpected_data(
                "process starttime",
                format!("invalid starttime {starttime}: {e}"),
            )
        })
    }

    #[cfg(all(test, target_os = "linux"))]
    mod linux_tests {
        use super::{parse_proc_stat_starttime, parse_proc_status_ids};

        #[test]
        fn parse_proc_stat_starttime_handles_spaces_in_comm() {
            let stat = "123 (name with spaces) S 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 987654321 20";

            let starttime = parse_proc_stat_starttime(stat).expect("starttime");

            assert_eq!(starttime, 987_654_321);
        }

        #[test]
        fn parse_proc_status_ids_reads_real_ids() {
            let status =
                "Name:\ttest\nUid:\t1000\t1000\t1000\t1000\nGid:\t1001\t1001\t1001\t1001\n";

            let ids = parse_proc_status_ids(status).expect("status ids");

            assert_eq!(ids.uid, 1000);
            assert_eq!(ids.gid, 1001);
        }
    }
}

/// Query the kernel pidversion for a process.
///
/// Returns `None` when the platform has no audit-token pidversion concept or
/// when the OS refuses the lookup.
#[must_use]
pub fn kernel_pidversion(pid: libc::pid_t) -> Option<u32> {
    imp::kernel_pidversion(pid)
}

/// Return the OS owner uid for a process.
///
/// # Errors
///
/// Returns an OS error if the process cannot be inspected or the platform does
/// not support this lookup.
pub fn process_uid(pid: libc::pid_t) -> Result<u32, OsError> {
    imp::process_uid(pid)
}

/// Return the OS owner gid for a process.
///
/// # Errors
///
/// Returns an OS error if the process cannot be inspected or the platform does
/// not support this lookup.
pub fn process_gid(pid: libc::pid_t) -> Result<u32, OsError> {
    imp::process_gid(pid)
}

/// Return Linux procfs starttime ticks for a process.
///
/// # Errors
///
/// Returns an OS error if procfs cannot be read or the stat payload is malformed.
#[cfg(target_os = "linux")]
pub fn process_starttime_ticks(pid: libc::pid_t) -> Result<u64, OsError> {
    imp::process_starttime_ticks(pid)
}

/// Fold Linux procfs starttime ticks into the legacy 32-bit pidversion slot.
#[cfg(target_os = "linux")]
#[must_use]
pub fn starttime_ticks_to_pidversion(starttime_ticks: u64) -> u32 {
    imp::starttime_ticks_to_pidversion(starttime_ticks)
}

/// Return the executable path for a process when the OS exposes one.
#[must_use]
pub fn process_path(pid: libc::pid_t) -> Option<String> {
    imp::process_path(pid)
}
