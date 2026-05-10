//! Test binary for M003-S01-T06: exercises send(), write()-to-socket,
//! and syscall(SYS_CONNECT) to verify the expanded hook surface blocks
//! exfiltration through all three paths.
//!
//! Usage: expanded_hooks_probe <mode>
//!   mode = "send" | "write_socket" | "syscall_connect" | "write_file" | "write_pipe"
//!
//! Exit codes:
//!   0 — operation completed (allowed or non-network)
//!   2 — operation failed with EHOSTUNREACH (Sentinel denied)
//!   3 — unexpected error
//!   4 — usage error

use std::io::Write as _;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        eprintln!("usage: expanded_hooks_probe <mode>");
        std::process::exit(4);
    }

    let deny_host = std::env::var("SENTINEL_DENY_HOST").unwrap_or_else(|_| "discord.com".into());
    let deny_port: u16 = std::env::var("SENTINEL_DENY_PORT")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(443);

    match args[1].as_str() {
        "send" => test_send(&deny_host, deny_port),
        "write_socket" => test_write_socket(&deny_host, deny_port),
        "syscall_connect" => test_syscall_connect(&deny_host, deny_port),
        "write_file" => test_write_file(),
        "write_pipe" => test_write_pipe(),
        other => {
            eprintln!("unknown mode: {other}");
            std::process::exit(4);
        }
    }
}

/// Test send() on a connected socket to a non-allowed host.
fn test_send(host: &str, port: u16) {
    // First, connect to the host (this should be denied by Sentinel).
    let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0) };
    if fd < 0 {
        eprintln!("socket() failed");
        std::process::exit(3);
    }

    let addr = resolve_host(host, port);
    let ret = unsafe { libc::connect(fd, &addr as *const _ as *const libc::sockaddr, std::mem::size_of::<libc::sockaddr_in>() as u32) };
    if ret < 0 {
        let errno = unsafe { *libc::__error() };
        if errno == libc::EHOSTUNREACH {
            println!("CONNECT-DENIED-EHOSTUNREACH");
            unsafe { libc::close(fd); }
            std::process::exit(2);
        }
        eprintln!("connect() failed with errno={errno}");
        unsafe { libc::close(fd); }
        std::process::exit(3);
    }

    // If connect succeeded, try send().
    let data = b"GET / HTTP/1.0\r\n\r\n";
    let ret = unsafe {
        libc::send(fd, data.as_ptr() as *const libc::c_void, data.len(), 0)
    };
    if ret < 0 {
        let errno = unsafe { *libc::__error() };
        println!("SEND-FAILED errno={errno}");
        unsafe { libc::close(fd); }
        std::process::exit(if errno == libc::EHOSTUNREACH { 2 } else { 3 });
    }

    println!("SEND-OK bytes={ret}");
    unsafe { libc::close(fd); }
    std::process::exit(0);
}

/// Test write() on a connected socket to a non-allowed host.
fn test_write_socket(host: &str, port: u16) {
    let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0) };
    if fd < 0 {
        eprintln!("socket() failed");
        std::process::exit(3);
    }

    let addr = resolve_host(host, port);
    let ret = unsafe { libc::connect(fd, &addr as *const _ as *const libc::sockaddr, std::mem::size_of::<libc::sockaddr_in>() as u32) };
    if ret < 0 {
        let errno = unsafe { *libc::__error() };
        if errno == libc::EHOSTUNREACH {
            println!("CONNECT-DENIED-EHOSTUNREACH");
            unsafe { libc::close(fd); }
            std::process::exit(2);
        }
        eprintln!("connect() failed with errno={errno}");
        unsafe { libc::close(fd); }
        std::process::exit(3);
    }

    // write() on the connected socket.
    let data = b"GET / HTTP/1.0\r\n\r\n";
    let ret = unsafe {
        libc::write(fd, data.as_ptr() as *const libc::c_void, data.len())
    };
    if ret < 0 {
        let errno = unsafe { *libc::__error() };
        println!("WRITE-FAILED errno={errno}");
        unsafe { libc::close(fd); }
        std::process::exit(if errno == libc::EHOSTUNREACH { 2 } else { 3 });
    }

    println!("WRITE-OK bytes={ret}");
    unsafe { libc::close(fd); }
    std::process::exit(0);
}

/// Test syscall(SYS_CONNECT, ...) to bypass function-level hooks.
fn test_syscall_connect(host: &str, port: u16) {
    let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0) };
    if fd < 0 {
        eprintln!("socket() failed");
        std::process::exit(3);
    }

    let addr = resolve_host(host, port);
    // Use libc::syscall(SYS_CONNECT, ...) — this is the bypass attempt
    // that T04's interpose should catch.
    const SYS_CONNECT: libc::c_int = 98;
    let ret = unsafe {
        libc::syscall(
            SYS_CONNECT,
            fd,
            &addr as *const _ as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_in>() as u32,
        )
    };
    if ret < 0 {
        let errno = unsafe { *libc::__error() };
        if errno == libc::EHOSTUNREACH {
            println!("SYSCALL-CONNECT-DENIED-EHOSTUNREACH");
            unsafe { libc::close(fd); }
            std::process::exit(2);
        }
        eprintln!("syscall(SYS_CONNECT) failed with errno={errno}");
        unsafe { libc::close(fd); }
        std::process::exit(3);
    }

    println!("SYSCALL-CONNECT-OK");
    unsafe { libc::close(fd); }
    std::process::exit(0);
}

/// Test write() to a regular file — must NOT be affected by the hook.
fn test_write_file() {
    let path = std::env::temp_dir().join("sentinel_write_test.tmp");
    let mut f = std::fs::File::create(&path).expect("create temp file");
    f.write_all(b"hello from write_file test").expect("write");
    drop(f);
    let contents = std::fs::read_to_string(&path).expect("read back");
    let _ = std::fs::remove_file(&path);
    if contents == "hello from write_file test" {
        println!("WRITE-FILE-OK");
        std::process::exit(0);
    } else {
        eprintln!("write content mismatch");
        std::process::exit(3);
    }
}

/// Test write() to a pipe — must NOT be affected by the hook.
fn test_write_pipe() {
    let mut fds = [0i32; 2];
    let ret = unsafe { libc::pipe(fds.as_mut_ptr()) };
    if ret < 0 {
        eprintln!("pipe() failed");
        std::process::exit(3);
    }
    let data = b"pipe-test-data";
    let written = unsafe { libc::write(fds[1], data.as_ptr() as *const libc::c_void, data.len()) };
    unsafe { libc::close(fds[1]); }
    if written < 0 {
        let errno = unsafe { *libc::__error() };
        eprintln!("write(pipe) failed errno={errno}");
        unsafe { libc::close(fds[0]); }
        std::process::exit(3);
    }
    let mut buf = [0u8; 64];
    let read = unsafe { libc::read(fds[0], buf.as_mut_ptr() as *mut libc::c_void, buf.len()) };
    unsafe { libc::close(fds[0]); }
    if read == written && &buf[..read as usize] == data {
        println!("WRITE-PIPE-OK");
        std::process::exit(0);
    } else {
        eprintln!("pipe read/write mismatch");
        std::process::exit(3);
    }
}

fn resolve_host(host: &str, port: u16) -> libc::sockaddr_in {
    use std::net::ToSocketAddrs;
    let addr_str = format!("{host}:{port}");
    let socket_addr = addr_str
        .to_socket_addrs()
        .expect("DNS resolution")
        .find(|a| a.is_ipv4())
        .expect("at least one IPv4 address");
    match socket_addr {
        std::net::SocketAddr::V4(v4) => {
            let mut sin: libc::sockaddr_in = unsafe { std::mem::zeroed() };
            sin.sin_len = std::mem::size_of::<libc::sockaddr_in>() as u8;
            sin.sin_family = libc::AF_INET as u8;
            sin.sin_port = port.to_be();
            sin.sin_addr.s_addr = u32::from_ne_bytes(v4.ip().octets());
            sin
        }
        _ => unreachable!(),
    }
}
