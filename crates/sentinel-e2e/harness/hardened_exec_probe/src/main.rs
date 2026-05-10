//! Test binary for M003-S02: exercises exec of hardened-runtime binaries
//! to verify the exec-blocking policy.
//!
//! Usage: hardened_exec_probe <mode>
//!   mode = "exec_curl"       — try to execve /usr/bin/curl
//!          "exec_env"        — try to execve /usr/bin/env (should NOT be blocked)
//!          "posix_spawn_curl" — try to posix_spawn /usr/bin/curl
//!
//! Exit codes:
//!   0 — exec succeeded (or child ran successfully for posix_spawn)
//!   2 — exec failed with EACCES (Sentinel blocked it)
//!   3 — unexpected error
//!   4 — usage error

use std::ffi::CString;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        eprintln!("usage: hardened_exec_probe <mode>");
        std::process::exit(4);
    }

    match args[1].as_str() {
        "exec_curl" => test_exec_curl(),
        "exec_env" => test_exec_env(),
        "posix_spawn_curl" => test_posix_spawn_curl(),
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

    let ret = unsafe {
        libc::execve(
            path.as_ptr(),
            argv.as_ptr(),
            std::ptr::null(),
        )
    };
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
    let argv = [arg0.as_ptr(), arg1.as_ptr(), arg2.as_ptr(), std::ptr::null()];

    let ret = unsafe {
        libc::execve(
            path.as_ptr(),
            argv.as_ptr(),
            std::ptr::null(),
        )
    };
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
