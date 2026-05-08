//! Phase 07 plan 03 task 2 — RED test pinning the new `status::*` submodules
//! and their `pub fn run` shapes. Compile-time signature pin (no daemon
//! required); also re-asserts that `status::run_status` is still reachable
//! at the same path (the bare-status path must keep working through the
//! status.rs → status/mod.rs migration).

use sentinel_cli::status::{denials, review, rules, trust};
use sentinel_cli::status::run_status;
use sentinel_cli::CliError;
use std::path::Path;

#[test]
fn status_rules_run_signature_pinned() {
    let _: fn(&Path, bool, bool, bool) -> Result<i32, CliError> = rules::run;
}

#[test]
fn status_trust_run_signature_pinned() {
    let _: fn(&Path, bool) -> Result<i32, CliError> = trust::run;
}

#[test]
fn status_denials_run_signature_pinned() {
    let _: fn(&str, bool) -> Result<i32, CliError> = denials::run;
}

#[test]
fn status_review_run_signature_pinned() {
    let _: fn(&Path, Option<String>) -> Result<i32, CliError> = review::run;
}

#[test]
fn status_run_status_still_reachable() {
    // The bare `sentinel status` path stays at crate::status::run_status —
    // the status.rs → status/mod.rs move must not break this re-export.
    let _: fn(&Path, &Path, bool, bool) -> Result<i32, CliError> = run_status;
}
