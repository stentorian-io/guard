//! Build the release dylib and verify __DATA,__interpose section size
//! matches 4 records × 16 bytes = 64 bytes (0x40).

use std::process::Command;

#[test]
fn release_dylib_has_four_interpose_records() {
    let out = Command::new("cargo")
        .args(["build", "-p", "sentinel-hook", "--release"])
        .output()
        .expect("cargo build");
    assert!(
        out.status.success(),
        "cargo build --release failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let dylib = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/release/libsentinel_hook.dylib");
    assert!(dylib.exists(), "expected dylib at {:?}", dylib);

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
    // 4 records: connect, connectx, sendto, sendmsg.
    // getaddrinfo was removed in plan 01-09: DYLD_INSERT_LIBRARIES patches every
    // symbol-table path, so the real connect cannot be reached via dlsym(RTLD_NEXT)
    // from inside our shadow. Connect-level IP allowlisting suffices for Phase 1;
    // a safer getaddrinfo strategy is deferred to a later phase.
    assert_eq!(
        size,
        4 * 16,
        "expected 4 records × 16 bytes = 64; got {size} (otool full text head: {})",
        text.lines().take(40).collect::<Vec<_>>().join("\n")
    );
}
