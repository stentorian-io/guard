use std::ffi::CString;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        eprintln!("usage: persistence_write_probe <path>");
        std::process::exit(1);
    }
    let path = CString::new(args[1].as_str()).expect("CString");

    let fd = unsafe {
        libc::open(
            path.as_ptr(),
            libc::O_WRONLY | libc::O_CREAT | libc::O_TRUNC,
            0o644 as libc::c_uint,
        )
    };
    if fd < 0 {
        let err = std::io::Error::last_os_error();
        eprintln!("open failed: {err}");
        std::process::exit(2);
    }
    let msg = b"persistence payload\n";
    let written = unsafe { libc::write(fd, msg.as_ptr() as *const libc::c_void, msg.len()) };
    unsafe { libc::close(fd) };

    if written < 0 {
        eprintln!("write failed");
        std::process::exit(3);
    }

    println!("WRITE-OK");
}
