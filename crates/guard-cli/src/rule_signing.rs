//! Rule authenticity signing for persistent user rules.
//!
//! Production signing must use hardware-backed private keys. This vertical slice
//! enforces that contract by failing closed when no hardware provider is
//! available; CI can opt into the explicit `test-signer` feature to exercise the
//! signed-rule flow without claiming hardware coverage.

use crate::CliError;
use guard_core::{
    ManagementActionPayloadV1, RuleSignaturePayloadV1, RuleSignatureV1, SnapshotSignaturePayloadV1,
    SnapshotSignatureV1,
};

/// Sign a persistent rule payload with the configured production or test signer.
///
/// # Errors
///
/// Returns an error when payload signing fails.
pub fn sign_rule_payload(payload: &RuleSignaturePayloadV1) -> Result<RuleSignatureV1, CliError> {
    sign_rule_payload_impl(payload)
}

/// Sign a snapshot payload with the configured production or test signer.
///
/// # Errors
///
/// Returns an error when payload signing fails.
pub fn sign_snapshot_payload(
    payload: &SnapshotSignaturePayloadV1,
) -> Result<SnapshotSignatureV1, CliError> {
    sign_snapshot_payload_impl(payload)
}

/// Sign a management action payload with the configured production or test signer.
///
/// # Errors
///
/// Returns an error when payload signing fails.
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
    crate::hardware_signing::sign_rule_payload(payload)
}

#[cfg(not(feature = "test-signer"))]
fn sign_snapshot_payload_impl(
    payload: &SnapshotSignaturePayloadV1,
) -> Result<SnapshotSignatureV1, CliError> {
    crate::hardware_signing::sign_snapshot_payload(payload)
}

#[cfg(not(feature = "test-signer"))]
fn sign_management_action_payload_impl(
    payload: &ManagementActionPayloadV1,
) -> Result<RuleSignatureV1, CliError> {
    crate::hardware_signing::sign_management_action_payload(payload)
}
