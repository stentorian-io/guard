//! Build the release dylib and verify __DATA,__interpose section size
//! matches the expected number of records × 16 bytes.
//!
//! v0.1 had 4 records (connect, connectx, sendto, sendmsg). v0.2 added 7 more
//! (fork, vfork, `posix_spawn`, `posix_spawnp`, execve, execvp, execv) —
//! execl/execlp/execle are intentionally OMITTED (variadic ABI; coverage is
//! preserved transitively via execve). M003-S01 added 3 more (send, write, writev).
//! M004-S04 added 1 more (getenv) for anti-detection hardening.
//! M005-S01 added 2 more (getaddrinfo, freeaddrinfo) for daemon-proxied DNS.
//! open/openat interpose disabled (`dispatch_once` reentrancy crash on macOS 26+).
//! libc `syscall()` interpose deferred (aarch64 C varargs ABI, Rust `c_variadic` unstable).
//! Total: 17 records.

use std::process::Command;

/// Total number of __DATA,__interpose records the release dylib must expose.
/// v0.1 = 4 (connect, connectx, sendto, sendmsg).
/// v0.2 = +7 (fork, vfork, `posix_spawn`, `posix_spawnp`, execve, execvp, execv).
/// M003-S01 = +3 (send, write, writev).
/// M004-S04 = +1 (getenv).
/// M005-S01 = +2 (getaddrinfo, freeaddrinfo).
const EXPECTED_INTERPOSE_RECORDS: u64 = 17;

#[test]
fn release_dylib_has_expected_interpose_records() {
    let out = Command::new("cargo")
        .args(["build", "-p", "guard-hook", "--release"])
        .output()
        .expect("cargo build");
    assert!(
        out.status.success(),
        "cargo build --release failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let target_dir =
        std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../target/release");
    let preferred = target_dir.join("stt-guard-hook.dylib");
    let dylib = if preferred.exists() {
        preferred
    } else {
        std::fs::read_dir(&target_dir)
            .expect("read target/release")
            .flatten()
            .map(|entry| entry.path())
            .find(|path| {
                path.file_name()
                    .and_then(|name| name.to_str())
                    .is_some_and(|name| {
                        std::path::Path::new(name)
                            .extension()
                            .is_some_and(|ext| ext.eq_ignore_ascii_case("dylib"))
                            && name.contains("hook")
                    })
            })
            .expect("expected a hook dylib in target/release")
    };
    assert!(dylib.exists(), "expected dylib at {dylib:?}");

    let otool = Command::new("otool")
        .args(["-l", dylib.to_str().unwrap()])
        .output()
        .expect("otool");
    let text = String::from_utf8_lossy(&otool.stdout);

    // Find a line `sectname __interpose` followed by a `size` line.
    let mut lines = text.lines();
    let mut found_size: Option<u64> = None;
    while let Some(l) = lines.next() {
        if l.trim() == "sectname __interpose" {
            for nl in lines.by_ref().take(8) {
                if let Some(rest) = nl.trim().strip_prefix("size") {
                    let s = rest.trim();
                    let n = if let Some(hex) = s.strip_prefix("0x") {
                        u64::from_str_radix(hex, 16).unwrap_or(0)
                    } else {
                        s.parse().unwrap_or(0)
                    };
                    found_size = Some(n);
                    break;
                }
            }
            break;
        }
    }
    let size = found_size.expect("expected __interpose section in otool output");
    let expected_bytes = EXPECTED_INTERPOSE_RECORDS * 16;
    assert_eq!(
        size,
        expected_bytes,
        "expected {EXPECTED_INTERPOSE_RECORDS} records × 16 bytes = {expected_bytes}; got {size} (otool full text head: {})",
        text.lines().take(40).collect::<Vec<_>>().join("\n")
    );
}
