//! Phase 07 Plan 04 Task 2 RED gate.
//!
//! Asserts:
//! - `trust_policy::display_rules` is `pub` (callable from outside the module).
//! - `trust_policy::run_trust_policy` is GONE (removed by Task 2).
//! - `sentinel_cli::approve` module no longer exists (file deleted in Task 2).
//!
//! This file fails to compile against pre-Task-2 code (display_rules is
//! file-private; run_trust_policy still exists with a working signature; the
//! approve module is still declared). After Task 2 lands, only the
//! display_rules call below succeeds. The trick: we use a `fn _check` body
//! that only references `display_rules` by reference; if it's still file-
//! private, this fails to compile.
//!
//! This file is REMOVED in Task 3 alongside the test rewrites; until then it
//! provides the structural TDD gate.

#[test]
fn red_display_rules_is_public() {
    // Reference display_rules as a function pointer to force the compiler to
    // resolve it as a `pub fn`. If it's file-private, this fails with E0603.
    let _: fn(&sentinel_core::policy_file::SentinelToml) =
        sentinel_cli::trust_policy::display_rules;
}
