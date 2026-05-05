// Linker tweaks for the cdylib's __DATA,__interpose section retention.
// See .planning/phases/01-foundations-hook-hello-world/01-RESEARCH.md Pitfall 6.
fn main() {
    // Prevent ld-prime from dead-stripping module init/term sections.
    println!("cargo:rustc-link-arg=-Wl,-no_dead_strip_inits_and_terms");
    // Hook is macOS-only.
    if std::env::var_os("CARGO_CFG_TARGET_OS").as_deref() != Some(std::ffi::OsStr::new("macos")) {
        println!("cargo:warning=sentinel-hook only supports macOS; this build will produce an unloadable artifact.");
    }
}
