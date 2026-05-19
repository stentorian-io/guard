//! Touch ID / password gating via macOS LocalAuthentication framework.
//!
//! Shells out to a minimal Swift script that calls LAContext. This avoids
//! Objective-C block FFI complexity while using the native system auth UI
//! (Touch ID with password fallback on all Macs).
//!
//! The gate can be disabled via SENTINEL_SKIP_BIOMETRIC=1 for CI/testing.

use std::process::Command;

const SWIFT_AUTH_SCRIPT: &str = r#"
import LocalAuthentication
import Foundation
let ctx = LAContext()
let sem = DispatchSemaphore(value: 0)
var ok = false
ctx.evaluatePolicy(.deviceOwnerAuthentication, localizedReason: CommandLine.arguments[1]) { success, _ in
    ok = success
    sem.signal()
}
sem.wait()
exit(ok ? 0 : 1)
"#;

/// Prompt the user for Touch ID or password authentication.
/// Returns `true` if authentication succeeded, `false` otherwise.
///
/// Skipped (returns true) when:
/// - SENTINEL_SKIP_BIOMETRIC=1 is set
/// - `/usr/bin/swift` is not available
/// - The Swift process fails to launch
pub fn authenticate(reason: &str) -> bool {
    if std::env::var("SENTINEL_SKIP_BIOMETRIC").as_deref() == Ok("1") {
        return true;
    }

    let swift = "/usr/bin/swift";
    if !std::path::Path::new(swift).exists() {
        tracing::warn!("swift not found; skipping biometric gate");
        return true;
    }

    match Command::new(swift)
        .arg("-e")
        .arg(SWIFT_AUTH_SCRIPT)
        .arg(reason)
        .stdin(std::process::Stdio::inherit())
        .stdout(std::process::Stdio::inherit())
        .stderr(std::process::Stdio::piped())
        .status()
    {
        Ok(status) => status.success(),
        Err(e) => {
            tracing::warn!(error = %e, "biometric auth process failed to launch");
            true
        }
    }
}
