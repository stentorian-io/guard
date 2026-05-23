#[cfg(not(feature = "test-signer"))]
#[test]
fn production_rule_signing_fails_without_hardware_provider() {
    let payload = guard_core::RuleSignaturePayloadV1::new(
        "allow",
        "exact",
        "h.example.com",
        "approved",
        1_700_000_000_000,
        "test",
        None,
    );
    let err = guard_cli::rule_signing::sign_rule_payload(&payload)
        .expect_err("production must not fall back to software signing");
    assert!(err
        .to_string()
        .contains("hardware-backed signing key unavailable"));
}

#[cfg(feature = "test-signer")]
#[test]
fn test_signer_feature_signs_with_explicit_simulator_kind() {
    let payload = guard_core::RuleSignaturePayloadV1::new(
        "allow",
        "exact",
        "h.example.com",
        "approved",
        1_700_000_000_000,
        "test",
        None,
    );
    let sig = guard_cli::rule_signing::sign_rule_payload(&payload).expect("test signer");
    assert_eq!(sig.signer_kind, guard_core::SIGNER_KIND_TEST_SIMULATOR);
}
