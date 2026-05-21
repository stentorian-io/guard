// Linker tweaks for the cdylib's __DATA,__interpose section retention.
fn main() {
    println!("cargo:rerun-if-changed=../sentinel-core/data/trusted-runtimes.yaml");
    // Prevent ld-prime from dead-stripping module init/term sections.
    println!("cargo:rustc-link-arg=-Wl,-no_dead_strip_inits_and_terms");
    // libobjc link removed: on macOS 26+, explicitly linking libobjc in a
    // Rust cdylib loaded via DYLD_INSERT_LIBRARIES changes dyld's init order,
    // contributing to dispatch_once reentrancy crashes in Network.framework.
    // The Objective-C runtime is already loaded by libSystem; object_getClassName
    // resolves via RTLD_DEFAULT without an explicit link directive.
    // println!("cargo:rustc-link-lib=dylib=objc");
    // Hook is macOS-only.
    if std::env::var_os("CARGO_CFG_TARGET_OS").as_deref() != Some(std::ffi::OsStr::new("macos")) {
        println!("cargo:warning=sentinel-hook only supports macOS; this build will produce an unloadable artifact.");
    }
}
