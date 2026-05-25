//! Rule authenticity signing for persistent user rules.
//!
//! Production signing uses ML-DSA-65 so first-release policy artifacts are
//! post-quantum from the start. CI can opt into the explicit `test-signer`
//! feature to exercise the signed-rule flow without claiming production signing
//! coverage.

use crate::CliError;
use guard_core::{
    ManagementActionPayloadV1, RuleSignaturePayloadV1, RuleSignatureV1, SnapshotSignaturePayloadV1,
    SnapshotSignatureV1,
};

pub fn sign_rule_payload(payload: &RuleSignaturePayloadV1) -> Result<RuleSignatureV1, CliError> {
    sign_rule_payload_impl(payload)
}

pub fn sign_snapshot_payload(
    payload: &SnapshotSignaturePayloadV1,
) -> Result<SnapshotSignatureV1, CliError> {
    sign_snapshot_payload_impl(payload)
}

pub fn sign_management_action_payload(
    payload: &ManagementActionPayloadV1,
) -> Result<RuleSignatureV1, CliError> {
    sign_management_action_payload_impl(payload)
}

#[cfg(feature = "test-signer")]
fn sign_rule_payload_impl(payload: &RuleSignaturePayloadV1) -> Result<RuleSignatureV1, CliError> {
    guard_core::rule_signature::test_support::sign_with_test_simulator(payload)
        .map_err(|e| CliError::Other(format!("test rule signer failed: {e}")))
}

#[cfg(feature = "test-signer")]
fn sign_snapshot_payload_impl(
    payload: &SnapshotSignaturePayloadV1,
) -> Result<SnapshotSignatureV1, CliError> {
    guard_core::rule_signature::test_support::sign_snapshot_with_test_simulator(payload)
        .map_err(|e| CliError::Other(format!("test snapshot signer failed: {e}")))
}

#[cfg(feature = "test-signer")]
fn sign_management_action_payload_impl(
    payload: &ManagementActionPayloadV1,
) -> Result<RuleSignatureV1, CliError> {
    guard_core::rule_signature::test_support::sign_management_action_with_test_simulator(payload)
        .map_err(|e| CliError::Other(format!("test management-action signer failed: {e}")))
}

#[cfg(not(feature = "test-signer"))]
fn sign_rule_payload_impl(payload: &RuleSignaturePayloadV1) -> Result<RuleSignatureV1, CliError> {
    crate::pq_signing::sign_rule_payload(payload)
}

#[cfg(not(feature = "test-signer"))]
fn sign_snapshot_payload_impl(
    payload: &SnapshotSignaturePayloadV1,
) -> Result<SnapshotSignatureV1, CliError> {
    crate::pq_signing::sign_snapshot_payload(payload)
}

#[cfg(not(feature = "test-signer"))]
fn sign_management_action_payload_impl(
    payload: &ManagementActionPayloadV1,
) -> Result<RuleSignatureV1, CliError> {
    crate::pq_signing::sign_management_action_payload(payload)
}
