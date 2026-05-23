#![cfg(feature = "test-signer")]

use guard_core::{
    verify_rule_signature, RuleSignaturePayloadV1, RuleSignaturePolicy, SIGNER_KIND_TEST_SIMULATOR,
};

fn payload() -> RuleSignaturePayloadV1 {
    RuleSignaturePayloadV1::new(
        "allow",
        "exact",
        "registry.example.com",
        "approved",
        1_700_000_000_000,
        "test",
        Some("run-1".into()),
    )
}

#[test]
fn test_simulator_signature_verifies_under_test_policy() {
    let payload = payload();
    let signature =
        guard_core::rule_signature::test_support::sign_with_test_simulator(&payload).expect("sign");
    assert_eq!(signature.signer_kind, SIGNER_KIND_TEST_SIMULATOR);
    verify_rule_signature(
        &payload,
        &signature,
        RuleSignaturePolicy::AllowTestSimulator,
    )
    .expect("verify");
}

#[test]
fn test_simulator_signature_is_rejected_under_production_policy() {
    let payload = payload();
    let signature =
        guard_core::rule_signature::test_support::sign_with_test_simulator(&payload).expect("sign");
    let err = verify_rule_signature(&payload, &signature, RuleSignaturePolicy::Production)
        .expect_err("production must reject simulator");
    assert!(err.to_string().contains("unsupported rule signer kind"));
}

#[test]
fn tampered_payload_fails_verification() {
    let payload = payload();
    let signature =
        guard_core::rule_signature::test_support::sign_with_test_simulator(&payload).expect("sign");
    let mut tampered = payload.clone();
    tampered.pattern = "evil.example.com".into();
    let err = verify_rule_signature(
        &tampered,
        &signature,
        RuleSignaturePolicy::AllowTestSimulator,
    )
    .expect_err("tampered payload must fail");
    assert!(err.to_string().contains("payload hash mismatch"));
}

#[test]
fn tampered_signature_fails_verification() {
    let payload = payload();
    let mut signature =
        guard_core::rule_signature::test_support::sign_with_test_simulator(&payload).expect("sign");
    signature.signature_der[8] ^= 0x55;
    let err = verify_rule_signature(
        &payload,
        &signature,
        RuleSignaturePolicy::AllowTestSimulator,
    )
    .expect_err("tampered signature must fail");
    assert!(
        err.to_string().contains("signature mismatch")
            || err.to_string().contains("invalid signature encoding")
    );
}
