#![cfg(feature = "test-signer")]

use guard_core::{
    ManagementActionPayloadV1, RULE_SIGNATURE_SCHEME_ML_DSA_65_SHA256, RuleSignaturePayloadV1,
    RuleSignaturePolicy, RuleSignatureV1, SIGNER_KIND_SOFTWARE_ML_DSA, SIGNER_KIND_TEST_SIMULATOR,
    SnapshotSignaturePayloadV1, sha256_hex, verify_management_action_signature,
    verify_rule_signature, verify_snapshot_signature,
};
use pqcrypto_mldsa::mldsa65;
use pqcrypto_traits::sign::{DetachedSignature as _, PublicKey as _};

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

fn snapshot_payload() -> SnapshotSignaturePayloadV1 {
    SnapshotSignaturePayloadV1::new(
        "run-1",
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        1_700_000_000_000,
    )
}

fn management_payload() -> ManagementActionPayloadV1 {
    ManagementActionPayloadV1::new(
        "disable-curated-rule",
        "registry.npmjs.org",
        "suspected compromise",
        1_700_000_000_000,
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
fn ml_dsa_signature_verifies_under_production_policy() {
    let payload = payload();
    let payload_bytes = guard_core::canonical_rule_payload_bytes(&payload).expect("encode");
    let (public_key, secret_key) = mldsa65::keypair();
    let signature = mldsa65::detached_sign(&payload_bytes, &secret_key);
    let public_key_bytes = public_key.as_bytes().to_vec();
    let signature = RuleSignatureV1 {
        scheme: RULE_SIGNATURE_SCHEME_ML_DSA_65_SHA256.to_string(),
        signer_kind: SIGNER_KIND_SOFTWARE_ML_DSA.to_string(),
        public_key_sha256: sha256_hex(&public_key_bytes),
        public_key_x963: public_key_bytes,
        signature_der: signature.as_bytes().to_vec(),
        signed_payload_sha256: sha256_hex(&payload_bytes),
        signature_created_at_unix_ms: payload.created_at_unix_ms,
    };

    verify_rule_signature(&payload, &signature, RuleSignaturePolicy::Production).expect("verify");
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

#[test]
fn snapshot_test_simulator_signature_verifies_under_test_policy() {
    let payload = snapshot_payload();
    let signature =
        guard_core::rule_signature::test_support::sign_snapshot_with_test_simulator(&payload)
            .expect("sign snapshot");
    assert_eq!(signature.signer_kind, SIGNER_KIND_TEST_SIMULATOR);
    verify_snapshot_signature(
        &payload,
        &signature,
        RuleSignaturePolicy::AllowTestSimulator,
    )
    .expect("verify snapshot");
}

#[test]
fn management_action_signature_verifies_under_test_policy() {
    let payload = management_payload();
    let signature =
        guard_core::rule_signature::test_support::sign_management_action_with_test_simulator(
            &payload,
        )
        .expect("sign management action");
    verify_management_action_signature(
        &payload,
        &signature,
        RuleSignaturePolicy::AllowTestSimulator,
    )
    .expect("verify management action");
}

#[test]
fn tampered_management_action_fails_verification() {
    let payload = management_payload();
    let signature =
        guard_core::rule_signature::test_support::sign_management_action_with_test_simulator(
            &payload,
        )
        .expect("sign management action");
    let mut tampered = payload.clone();
    tampered.action = "enable-curated-rule".into();
    let err = verify_management_action_signature(
        &tampered,
        &signature,
        RuleSignaturePolicy::AllowTestSimulator,
    )
    .expect_err("tampered management action must fail");
    assert!(err.to_string().contains("payload hash mismatch"));
}

#[test]
fn snapshot_test_simulator_signature_is_rejected_under_production_policy() {
    let payload = snapshot_payload();
    let signature =
        guard_core::rule_signature::test_support::sign_snapshot_with_test_simulator(&payload)
            .expect("sign snapshot");
    let err = verify_snapshot_signature(&payload, &signature, RuleSignaturePolicy::Production)
        .expect_err("production must reject simulator");
    assert!(err.to_string().contains("unsupported rule signer kind"));
}

#[test]
fn tampered_snapshot_payload_fails_verification() {
    let payload = snapshot_payload();
    let signature =
        guard_core::rule_signature::test_support::sign_snapshot_with_test_simulator(&payload)
            .expect("sign snapshot");
    let mut tampered = payload.clone();
    tampered.snapshot_sha256 =
        "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff".to_string();
    let err = verify_snapshot_signature(
        &tampered,
        &signature,
        RuleSignaturePolicy::AllowTestSimulator,
    )
    .expect_err("tampered snapshot payload must fail");
    assert!(err.to_string().contains("payload hash mismatch"));
}

#[test]
fn tampered_snapshot_signature_fails_verification() {
    let payload = snapshot_payload();
    let mut signature =
        guard_core::rule_signature::test_support::sign_snapshot_with_test_simulator(&payload)
            .expect("sign snapshot");
    signature.signature_der[8] ^= 0x55;
    let err = verify_snapshot_signature(
        &payload,
        &signature,
        RuleSignaturePolicy::AllowTestSimulator,
    )
    .expect_err("tampered snapshot signature must fail");
    assert!(
        err.to_string().contains("signature mismatch")
            || err.to_string().contains("invalid signature encoding")
    );
}
