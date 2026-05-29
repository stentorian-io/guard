//! v0.3 — `ProcessTree` extensions for `is_tty/baseline_mode/prompt_channel`.

use crossbeam_channel::bounded;
use guard_daemon::tracked::ProcessTree;

#[test]
fn set_and_get_prompt_channel() {
    let tree = ProcessTree::new();
    let (tx, rx) = bounded::<guard_ipc::PromptRequest>(1);
    tree.set_prompt_channel("run-1", tx);
    assert!(tree.get_prompt_channel("run-1").is_some());
    let taken = tree.take_prompt_channel("run-1");
    assert!(taken.is_some());
    assert!(
        tree.get_prompt_channel("run-1").is_none(),
        "take_prompt_channel removes the entry"
    );
    drop(rx);
}

#[test]
fn set_run_fields_no_op_when_run_unknown() {
    let tree = ProcessTree::new();
    // Should not panic on unknown run_uuid.
    tree.set_run_is_tty("nonexistent", true);
    tree.set_run_baseline_mode("nonexistent", true);
}

// Note: full set_run_*_mode happy-path tests live in the PrepareSnapshot V3 field wiring.
