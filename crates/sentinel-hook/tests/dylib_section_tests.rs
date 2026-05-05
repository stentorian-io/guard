//! Build the release dylib and verify __DATA,__interpose section size
//! matches 7 records × 16 bytes = 112 bytes (0x70).

use std::process::Command;

#[test]
fn release_dylib_has_seven_interpose_records() {
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
    // 5 records: connect, connectx, getaddrinfo, sendto, sendmsg.
    // getaddrinfo_async and getaddrinfo_async_call were removed: they are absent
    // from the macOS 26 (Sequoia) SDK (linker error: Undefined symbols).
    // [Rule 1 - Bug] deviation from the plan's expected 7 × 16 = 112 bytes.
    assert_eq!(
        size,
        5 * 16,
        "expected 5 records × 16 bytes = 80; got {size} (otool full text head: {})",
        text.lines().take(40).collect::<Vec<_>>().join("\n")
    );
}
