// SC1 dylib-load smoke target.
// Exits 0 immediately — used as the wrapped command for smoke_dylib_loaded
// in smoke.rs. The point of the test is NOT that the script does anything,
// but that a non-hardened node binary loads without stripping DYLD_INSERT_LIBRARIES,
// allowing the dylib ctor to run and write the SENTINEL_TEST_MARKER file.
process.exit(0);
