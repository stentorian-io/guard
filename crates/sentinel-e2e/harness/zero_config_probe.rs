//! Harness probe for the zero_config_allow_deny e2e test.
//!
//! Usage: `zero_config_probe <addr_a> <addr_b>`
//! Both addrs must be `<host>:<port>` strings — IP literal hosts only (the
//! probe deliberately uses `addr.parse()` to bypass getaddrinfo so the test
//! exercises the dylib's libc connect() shadow specifically).
//!
//! Exit code is a bitmask:
//!   bit 0 (value 1) = addr_a connect succeeded
//!   bit 1 (value 2) = addr_b connect succeeded
//! Expected outcomes:
//!   - Without sentinel run: 3 (both succeed)
//!   - Under sentinel run with addr_a allowlisted, addr_b not: 1 (only A)

use std::net::TcpStream;
use std::time::Duration;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 3 {
        eprintln!("usage: zero_config_probe <addr_a> <addr_b>");
        std::process::exit(255);
    }
    let mut bits: i32 = 0;
    if try_connect(&args[1]) {
        bits |= 1;
    }
    if try_connect(&args[2]) {
        bits |= 2;
    }
    eprintln!(
        "probe: addr_a={} addr_b={} bits={}",
        args[1], args[2], bits
    );
    std::process::exit(bits);
}

fn try_connect(addr: &str) -> bool {
    let parsed = match addr.parse() {
        Ok(p) => p,
        Err(e) => {
            eprintln!("probe: parse {addr} failed: {e}");
            return false;
        }
    };
    match TcpStream::connect_timeout(&parsed, Duration::from_millis(500)) {
        Ok(_) => true,
        Err(e) => {
            eprintln!("probe: connect {addr} failed: {} ({:?})", e, e.kind());
            false
        }
    }
}
