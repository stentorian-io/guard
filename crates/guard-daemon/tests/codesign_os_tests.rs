use guard_os::codesign::{
    CS_HARD, CS_OPS_STATUS, CS_REQUIRE_LV, CS_RESTRICT, CS_RUNTIME, SYS_CSOPS, csops_status,
    has_hardened_bits, is_hardened_runtime,
};

#[test]
fn constants_have_expected_values() {
    assert_eq!(SYS_CSOPS, 169);
    assert_eq!(CS_OPS_STATUS, 0);
    assert_eq!(CS_HARD, 0x100);
    assert_eq!(CS_RESTRICT, 0x800);
    assert_eq!(CS_REQUIRE_LV, 0x2000);
    assert_eq!(CS_RUNTIME, 0x10000);
}

#[test]
fn csops_on_self_returns_some_flags() {
    let pid = unsafe { libc::getpid() };
    let r = csops_status(pid);
    assert!(r.is_ok(), "csops on self should succeed; got {r:?}");
}

#[test]
fn csops_on_invalid_pid_returns_err() {
    // Use a clearly-invalid pid. macOS pids fit in 32 bits; very large values are reliably absent.
    let r = csops_status(99_999_999);
    assert!(r.is_err(), "csops on invalid pid should fail");
}

#[test]
fn is_hardened_runtime_on_self_is_false_for_unhardened_test_binary() {
    let pid = unsafe { libc::getpid() };
    // Cargo-built unit-test binaries are NOT hardened-runtime by default.
    assert!(
        !is_hardened_runtime(pid),
        "test binary should not be hardened-runtime"
    );
}

#[test]
fn is_hardened_runtime_on_invalid_pid_is_false_conservative() {
    assert!(!is_hardened_runtime(99_999_999));
}

#[test]
fn has_hardened_bits_detects_each_flag_alone() {
    assert!(has_hardened_bits(CS_RESTRICT));
    assert!(has_hardened_bits(CS_RUNTIME));
    assert!(has_hardened_bits(CS_HARD));
    assert!(has_hardened_bits(CS_REQUIRE_LV));
    assert!(!has_hardened_bits(0));
    assert!(!has_hardened_bits(0x4000)); // unrelated bit
}

#[test]
fn has_hardened_bits_detects_combinations() {
    assert!(has_hardened_bits(CS_RESTRICT | CS_RUNTIME));
    assert!(has_hardened_bits(CS_HARD | CS_REQUIRE_LV | 0x4000));
}
