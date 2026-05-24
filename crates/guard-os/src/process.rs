//! Process inspection primitives.

#[cfg(target_os = "macos")]
mod imp {
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
}

#[cfg(not(target_os = "macos"))]
mod imp {
    pub fn kernel_pidversion(_pid: libc::pid_t) -> Option<u32> {
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
