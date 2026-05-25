#[cfg(not(feature = "test-signer"))]
#[test]
fn production_rule_signing_fails_when_pq_signer_is_disabled() {
    let payload = guard_core::RuleSignaturePayloadV1::new(
        "allow",
        "exact",
        "h.example.com",
        "approved",
        1_700_000_000_000,
        "test",
        None,
    );
    unsafe {
        std::env::set_var("STT_GUARD_DISABLE_PQ_SIGNER", "1");
    }
    let err = guard_cli::rule_signing::sign_rule_payload(&payload)
        .expect_err("production signing must fail when the PQ signer is disabled");
    assert!(err.to_string().contains("ML-DSA signing key unavailable"));

    let snapshot_payload = guard_core::SnapshotSignaturePayloadV1::new(
        "run-1",
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        1_700_000_000_000,
    );
    let err = guard_cli::rule_signing::sign_snapshot_payload(&snapshot_payload)
        .expect_err("production snapshot signing must fail when the PQ signer is disabled");
    assert!(err.to_string().contains("ML-DSA signing key unavailable"));
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

    let snapshot_payload = guard_core::SnapshotSignaturePayloadV1::new(
        "run-1",
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        1_700_000_000_000,
    );
    let sig = guard_cli::rule_signing::sign_snapshot_payload(&snapshot_payload)
        .expect("test snapshot signer");
    assert_eq!(sig.signer_kind, guard_core::SIGNER_KIND_TEST_SIMULATOR);
}
