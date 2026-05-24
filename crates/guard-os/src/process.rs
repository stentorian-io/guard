//! Process inspection primitives.

use crate::OsError;

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

    pub fn kernel_pidversion(pid: libc::pid_t) -> Option<u32> {
        unsafe {
            let mut task_port: MachPortT = MACH_PORT_NULL;
            let kr = task_name_for_pid(mach_task_self(), pid, &mut task_port);
            if kr != KERN_SUCCESS {
                return None;
            }
            let mut token_val = [0u32; 8];
            let mut count: u32 = 8;
            let kr2 = task_info(
                task_port,
                TASK_AUDIT_TOKEN,
                token_val.as_mut_ptr(),
                &mut count,
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
            let info_size = std::mem::size_of::<libc::proc_bsdinfo>() as libc::c_int;
            let n = libc::proc_pidinfo(
                pid,
                libc::PROC_PIDTBSDINFO,
                0,
                &mut info as *mut _ as *mut libc::c_void,
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

    pub fn process_path(pid: libc::pid_t) -> Option<String> {
        let mut buf = [0u8; libc::MAXPATHLEN as usize];
        let n = unsafe {
            libc::proc_pidpath(pid, buf.as_mut_ptr() as *mut libc::c_void, buf.len() as u32)
        };
        if n > 0 {
            Some(String::from_utf8_lossy(&buf[..n as usize]).to_string())
        } else {
            None
        }
    }
}

#[cfg(not(target_os = "macos"))]
mod imp {
    use super::*;

    pub fn kernel_pidversion(_pid: libc::pid_t) -> Option<u32> {
        None
    }

    pub fn process_uid(_pid: libc::pid_t) -> Result<u32, OsError> {
        Err(OsError::unsupported("process uid"))
    }

    pub fn process_path(_pid: libc::pid_t) -> Option<String> {
        None
    }
}

/// Query the kernel pidversion for a process.
///
/// Returns `None` when the platform has no audit-token pidversion concept or
/// when the OS refuses the lookup.
pub fn kernel_pidversion(pid: libc::pid_t) -> Option<u32> {
    imp::kernel_pidversion(pid)
}

/// Return the OS owner uid for a process.
pub fn process_uid(pid: libc::pid_t) -> Result<u32, OsError> {
    imp::process_uid(pid)
}

/// Return the executable path for a process when the OS exposes one.
pub fn process_path(pid: libc::pid_t) -> Option<String> {
    imp::process_path(pid)
}
