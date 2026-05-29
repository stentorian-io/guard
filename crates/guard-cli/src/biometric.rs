//! Touch ID / password gating via macOS `LocalAuthentication` framework.
//!
//! Shells out to a minimal Swift script that calls `LAContext`. This avoids
//! Objective-C block FFI complexity while using the native system auth UI
//! (Touch ID with password fallback on all Macs).
//!
//! Fail-closed: if Swift is unavailable or the process fails to launch,
//! authentication is denied.

#[cfg(not(feature = "test-signer"))]
use std::process::Command;

#[cfg(not(feature = "test-signer"))]
const SWIFT_AUTH_SCRIPT: &str = r"
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
";

/// Prompt the user for Touch ID or password authentication.
/// Returns `true` if authentication succeeded, `false` otherwise.
///
/// Fail-closed: returns `false` if `/usr/bin/swift` is missing or fails to launch.
#[cfg(feature = "test-signer")]
pub fn authenticate(reason: &str) -> bool {
    let _ = reason;
    true
}

/// Prompt the user for Touch ID or password authentication.
/// Returns `true` if authentication succeeded, `false` otherwise.
///
/// Fail-closed: returns `false` if `/usr/bin/swift` is missing or fails to launch.
#[cfg(not(feature = "test-signer"))]
pub fn authenticate(reason: &str) -> bool {
    let swift = "/usr/bin/swift";
    if !std::path::Path::new(swift).exists() {
        tracing::error!("swift not found — cannot perform biometric auth; denying");
        return false;
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
            tracing::error!(error = %e, "biometric auth process failed to launch; denying");
            false
        }
    }
}
