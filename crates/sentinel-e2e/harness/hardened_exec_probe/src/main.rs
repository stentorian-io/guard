//! Test binary for exec-time layered enforcement.
//!
//! Usage: hardened_exec_probe <mode>
//!   mode = "exec_curl"       — try to execve /usr/bin/curl
//!          "exec_env"        — try to execve /usr/bin/env
//!          "exec_env_delayed" — sleep briefly, then execve /usr/bin/env
//!          "posix_spawn_curl" — try to posix_spawn /usr/bin/curl
//!          "posix_spawn_env_delayed" — sleep, then posix_spawn /usr/bin/env
//!          "exec_synthetic_fat" — exec synthetic fat Mach-O (T0 block)
//!          "exec_synthetic_syscall" — exec synthetic thin Mach-O with syscall bytes (T3 fail-closed)
//!          "posix_spawn_synthetic_syscall_attr" — posix_spawn T3 with caller attrs (T3 fail-closed)
//!
//! Exit codes:
//!   0 — exec succeeded (or child ran successfully for posix_spawn)
//!   2 — exec failed with EACCES (Sentinel blocked it)
//!   3 — unexpected error
//!   4 — usage error

use std::ffi::CString;
use std::io::Write;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::PermissionsExt;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        eprintln!("usage: hardened_exec_probe <mode>");
        std::process::exit(4);
    }

    match args[1].as_str() {
        "exec_curl" => test_exec_curl(),
        "exec_env" => test_exec_env(),
        "exec_env_delayed" => {
            std::thread::sleep(std::time::Duration::from_millis(1500));
            test_exec_env();
        }
        "posix_spawn_curl" => test_posix_spawn_curl(),
        "posix_spawn_env_delayed" => {
            std::thread::sleep(std::time::Duration::from_millis(1500));
            test_posix_spawn_env();
        }
        "exec_synthetic_fat" => test_exec_synthetic_fat(),
        "exec_synthetic_syscall" => test_exec_synthetic_syscall(),
        "posix_spawn_synthetic_syscall_attr" => test_posix_spawn_synthetic_syscall_attr(),
        other => {
            eprintln!("unknown mode: {other}");
            std::process::exit(4);
        }
    }
}

fn test_exec_curl() {
    let path = CString::new("/usr/bin/curl").unwrap();
    let arg0 = CString::new("curl").unwrap();
    let arg1 = CString::new("--version").unwrap();
    let argv = [arg0.as_ptr(), arg1.as_ptr(), std::ptr::null()];

    let ret = unsafe { libc::execve(path.as_ptr(), argv.as_ptr(), std::ptr::null()) };
    if ret < 0 {
        let errno = unsafe { *libc::__error() };
        if errno == libc::EACCES {
            println!("EXEC-BLOCKED-EACCES");
            std::process::exit(2);
        }
        eprintln!("execve failed with errno={errno}");
        std::process::exit(3);
    }
    // execve doesn't return on success
}

fn test_exec_env() {
    let path = CString::new("/usr/bin/env").unwrap();
    let arg0 = CString::new("env").unwrap();
    let arg1 = CString::new("echo").unwrap();
    let arg2 = CString::new("ENV-EXEC-OK").unwrap();
    let argv = [
        arg0.as_ptr(),
        arg1.as_ptr(),
        arg2.as_ptr(),
        std::ptr::null(),
    ];

    let ret = unsafe { libc::execve(path.as_ptr(), argv.as_ptr(), std::ptr::null()) };
    if ret < 0 {
        let errno = unsafe { *libc::__error() };
        if errno == libc::EACCES {
            println!("EXEC-BLOCKED-EACCES");
            std::process::exit(2);
        }
        eprintln!("execve failed with errno={errno}");
        std::process::exit(3);
    }
}

fn test_posix_spawn_curl() {
    let path = CString::new("/usr/bin/curl").unwrap();
    let arg0 = CString::new("curl").unwrap();
    let arg1 = CString::new("--version").unwrap();
    let argv: Vec<*mut libc::c_char> = vec![
        arg0.as_ptr() as *mut _,
        arg1.as_ptr() as *mut _,
        std::ptr::null_mut(),
    ];

    let mut pid: libc::pid_t = 0;
    let ret = unsafe {
        libc::posix_spawn(
            &mut pid,
            path.as_ptr(),
            std::ptr::null(),
            std::ptr::null(),
            argv.as_ptr(),
            std::ptr::null_mut(),
        )
    };

    if ret == libc::EACCES {
        println!("POSIX-SPAWN-BLOCKED-EACCES");
        std::process::exit(2);
    }
    if ret != 0 {
        eprintln!("posix_spawn failed with errno={ret}");
        std::process::exit(3);
    }

    // Wait for child
    let mut status: libc::c_int = 0;
    unsafe { libc::waitpid(pid, &mut status, 0) };
    println!("POSIX-SPAWN-OK pid={pid}");
    std::process::exit(0);
}

fn test_posix_spawn_env() {
    let path = CString::new("/usr/bin/env").unwrap();
    let arg0 = CString::new("env").unwrap();
    let arg1 = CString::new("echo").unwrap();
    let arg2 = CString::new("ENV-POSIX-SPAWN-OK").unwrap();
    let argv: Vec<*mut libc::c_char> = vec![
        arg0.as_ptr() as *mut _,
        arg1.as_ptr() as *mut _,
        arg2.as_ptr() as *mut _,
        std::ptr::null_mut(),
    ];

    let mut pid: libc::pid_t = 0;
    let ret = unsafe {
        libc::posix_spawn(
            &mut pid,
            path.as_ptr(),
            std::ptr::null(),
            std::ptr::null(),
            argv.as_ptr(),
            std::ptr::null_mut(),
        )
    };

    if ret == libc::EACCES {
        println!("POSIX-SPAWN-BLOCKED-EACCES");
        std::process::exit(2);
    }
    if ret != 0 {
        eprintln!("posix_spawn failed with errno={ret}");
        std::process::exit(3);
    }

    let mut status: libc::c_int = 0;
    unsafe { libc::waitpid(pid, &mut status, 0) };
    println!("POSIX-SPAWN-ENV-OK pid={pid}");
    std::process::exit(0);
}

fn test_exec_synthetic_fat() {
    let path = write_executable_fixture("sentinel-fat", &fat_macho_fixture());
    let outcome = exec_fixture(&path);
    if outcome == ExecOutcome::Errno(libc::EACCES) {
        println!("SYNTHETIC-FAT-BLOCKED-EACCES");
        std::process::exit(2);
    }
    eprintln!("synthetic fat exec was not blocked; outcome={outcome:?}");
    std::process::exit(3);
}

fn test_exec_synthetic_syscall() {
    let path = write_executable_fixture("sentinel-syscall", &thin_syscall_fixture());
    let outcome = exec_fixture(&path);
    if outcome == ExecOutcome::Errno(libc::EACCES) {
        println!("SYNTHETIC-SYSCALL-BLOCKED-EACCES");
        std::process::exit(2);
    }
    eprintln!("synthetic syscall exec was not blocked; outcome={outcome:?}");
    std::process::exit(3);
}

fn test_posix_spawn_synthetic_syscall_attr() {
    let path = write_executable_fixture("sentinel-syscall-spawn", &thin_syscall_fixture());
    let c_path = CString::new(path.as_os_str().as_bytes()).expect("fixture path");
    let arg0 = CString::new("fixture").unwrap();
    let argv: Vec<*mut libc::c_char> = vec![arg0.as_ptr() as *mut _, std::ptr::null_mut()];
    let mut attr = std::ptr::null_mut();
    let attr_init = unsafe { libc::posix_spawnattr_init(&mut attr) };
    if attr_init != 0 {
        eprintln!("posix_spawnattr_init failed with errno={attr_init}");
        std::process::exit(3);
    }

    let mut pid: libc::pid_t = 0;
    let ret = unsafe {
        libc::posix_spawn(
            &mut pid,
            c_path.as_ptr(),
            std::ptr::null(),
            &attr,
            argv.as_ptr(),
            std::ptr::null_mut(),
        )
    };
    unsafe {
        libc::posix_spawnattr_destroy(&mut attr);
    }

    if ret == libc::ENOTSUP {
        println!("SYNTHETIC-SYSCALL-POSIX-SPAWN-ATTR-ENOTSUP");
        std::process::exit(2);
    }
    eprintln!("synthetic syscall posix_spawn attr was not rejected; errno={ret}");
    std::process::exit(3);
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ExecOutcome {
    Errno(libc::c_int),
    Returned(libc::c_int),
}

fn exec_fixture(path: &std::path::Path) -> ExecOutcome {
    let c_path = CString::new(path.as_os_str().as_bytes()).expect("fixture path");
    let arg0 = CString::new("fixture").unwrap();
    let argv = [arg0.as_ptr(), std::ptr::null()];
    let ret = unsafe { libc::execve(c_path.as_ptr(), argv.as_ptr(), std::ptr::null()) };
    if ret < 0 {
        ExecOutcome::Errno(unsafe { *libc::__error() })
    } else {
        ExecOutcome::Returned(ret)
    }
}

fn write_executable_fixture(name: &str, bytes: &[u8]) -> std::path::PathBuf {
    let path = std::env::temp_dir().join(format!("{name}-{}", std::process::id()));
    let mut file = std::fs::File::create(&path).expect("create synthetic Mach-O fixture");
    file.write_all(bytes)
        .expect("write synthetic Mach-O fixture");
    let mut perms = file.metadata().expect("fixture metadata").permissions();
    perms.set_mode(0o755);
    std::fs::set_permissions(&path, perms).expect("chmod synthetic Mach-O fixture");
    path
}

fn fat_macho_fixture() -> Vec<u8> {
    let mut data = vec![0u8; 8];
    data[0..4].copy_from_slice(&0xcafebabe_u32.to_be_bytes());
    data
}

fn thin_syscall_fixture() -> Vec<u8> {
    const MH_MAGIC_64: u32 = 0xfeedfacf;
    const LC_SEGMENT_64: u32 = 0x19;
    #[cfg(target_arch = "aarch64")]
    const NATIVE_CPU_TYPE: u32 = 0x0100_000c;
    #[cfg(target_arch = "x86_64")]
    const NATIVE_CPU_TYPE: u32 = 0x0100_0007;

    let payload: &[u8] = if cfg!(target_arch = "aarch64") {
        &[0xaa, 0x01, 0x10, 0x00, 0xd4]
    } else {
        &[0xaa, 0x0f, 0x05]
    };
    let fileoff = 0x100u64;
    let filesize = payload.len() as u64;
    let mut data = vec![0u8; fileoff as usize + payload.len()];
    data[0..4].copy_from_slice(&MH_MAGIC_64.to_le_bytes());
    data[4..8].copy_from_slice(&NATIVE_CPU_TYPE.to_le_bytes());
    data[16..20].copy_from_slice(&1u32.to_le_bytes());
    data[20..24].copy_from_slice(&72u32.to_le_bytes());

    let pos = 32usize;
    data[pos..pos + 4].copy_from_slice(&LC_SEGMENT_64.to_le_bytes());
    data[pos + 4..pos + 8].copy_from_slice(&72u32.to_le_bytes());
    data[pos + 8..pos + 14].copy_from_slice(b"__TEXT");
    data[pos + 40..pos + 48].copy_from_slice(&fileoff.to_le_bytes());
    data[pos + 48..pos + 56].copy_from_slice(&filesize.to_le_bytes());
    data[fileoff as usize..].copy_from_slice(payload);
    data
}
