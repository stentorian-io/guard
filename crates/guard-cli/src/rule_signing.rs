//! Rule authenticity signing for persistent user rules.
//!
//! Production signing must use hardware-backed private keys. This vertical slice
//! enforces that contract by failing closed when no hardware provider is
//! available; CI can opt into the explicit `test-signer` feature to exercise the
//! signed-rule flow without claiming hardware coverage.

use crate::CliError;
use guard_core::{RuleSignaturePayloadV1, RuleSignatureV1};

pub fn sign_rule_payload(payload: &RuleSignaturePayloadV1) -> Result<RuleSignatureV1, CliError> {
    sign_rule_payload_impl(payload)
}

#[cfg(feature = "test-signer")]
fn sign_rule_payload_impl(payload: &RuleSignaturePayloadV1) -> Result<RuleSignatureV1, CliError> {
    guard_core::rule_signature::test_support::sign_with_test_simulator(payload)
        .map_err(|e| CliError::Other(format!("test rule signer failed: {e}")))
}

#[cfg(not(feature = "test-signer"))]
fn sign_rule_payload_impl(_payload: &RuleSignaturePayloadV1) -> Result<RuleSignatureV1, CliError> {
    Err(CliError::Other(
        "hardware-backed signing key unavailable; software-only rule signing is unsupported".into(),
    ))
}
