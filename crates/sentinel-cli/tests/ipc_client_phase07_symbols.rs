//! Phase 07 plan 03 task 1 — RED test that pins the existence and signatures
//! of the three new `ipc_client` request functions: `list_rules_request`,
//! `list_trust_request`, `is_trusted_request`.
//!
//! We can't actually round-trip against the daemon in a unit-style integration
//! test (no daemon is running), so the test is a compile-time function-pointer
//! pin. If the signatures change shape (or the functions disappear), this
//! test stops compiling — which is exactly the regression-detection contract
//! Plan 03 task 1's acceptance criteria are after.

use sentinel_cli::ipc_client::{is_trusted_request, list_rules_request, list_trust_request};
use sentinel_cli::CliError;
use sentinel_ipc::{RuleRow, TrustRow};
use std::path::Path;

#[test]
fn list_rules_request_signature_pinned() {
    // The function exists with this exact signature:
    //   fn list_rules_request(&Path, bool, Option<String>) -> Result<Vec<RuleRow>, CliError>
    let _: fn(&Path, bool, Option<String>) -> Result<Vec<RuleRow>, CliError> =
        list_rules_request;
}

#[test]
fn list_trust_request_signature_pinned() {
    let _: fn(&Path) -> Result<Vec<TrustRow>, CliError> = list_trust_request;
}

#[test]
fn is_trusted_request_signature_pinned() {
    let _: fn(&Path, &str, &str) -> Result<bool, CliError> = is_trusted_request;
}
