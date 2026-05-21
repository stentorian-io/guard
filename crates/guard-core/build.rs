fn main() {
    // Link Apple's libbsm which provides audit_token_to_pid and audit_token_to_pidversion.
    // These functions live in the system's libbsm (shipped with macOS).
    #[cfg(target_os = "macos")]
    println!("cargo:rustc-link-lib=bsm");
}
