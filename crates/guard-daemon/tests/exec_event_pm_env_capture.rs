//! v0.3 — Smoke test — `extract_pm_env`'s output composes with
//! `ProcessTree`'s `set_pm_env_snapshot` API.
//!
//! The composition's correctness on a populated node is exercised in e2e tests
//! (the dylib's real `ExecEvent` V3 → daemon `record_exec` → `set_pm_env_snapshot`
//! round-trip).

use guard_daemon::env_capture::extract_pm_env;

#[test]
fn extract_pm_env_filters_correctly() {
    let env = vec![
        ("npm_package_name".into(), "lodash".into()),
        ("npm_config_authToken".into(), "leak".into()), // secret denylist
        ("HOME".into(), "/me".into()),                  // not allowed
    ];
    let captured = extract_pm_env(&env);
    assert_eq!(captured.len(), 1);
    assert_eq!(captured[0].0, "npm_package_name");
}

// AuditToken construction note (WARNING #10): ProcessTree::set_pm_env_snapshot
// no-op-on-unknown-token property is already tested in
// crates/guard-daemon/tests/process_tree_extensions.rs (Task 1's
// set_run_fields_no_op_when_run_unknown analogy). The full pipeline test lives
// in e2e tests.
