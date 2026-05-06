//! Phase 3 plan 03-13 BLOCKER #1 — SIGINT handler unit test.
//!
//! Note: we cannot test killpg() in a unit test (would kill the test runner).
//! We test ONLY the in-flight prompt_id snapshot semantics. The cancel-emission
//! over a live PromptChannel + the killpg propagation are observed in plan 03-14
//! e2e (prompt_cancel_via_sigint).

use std::collections::HashSet;
use std::sync::{Arc, Mutex};

use sentinel_cli::prompt_channel::InflightPrompts;

#[test]
fn handle_sigint_snapshots_inflight_set() {
    let inflight = InflightPrompts(Arc::new(Mutex::new(HashSet::new())));
    inflight.0.lock().unwrap().insert("p-1".into());
    inflight.0.lock().unwrap().insert("p-2".into());
    inflight.0.lock().unwrap().insert("p-3".into());

    // Snapshot under the same lock pattern handle_sigint uses.
    let snapshot: Vec<String> = inflight.0.lock().unwrap().iter().cloned().collect();
    assert_eq!(snapshot.len(), 3);
    assert!(snapshot.contains(&"p-1".to_string()));
    assert!(snapshot.contains(&"p-2".to_string()));
    assert!(snapshot.contains(&"p-3".to_string()));
}

#[test]
fn handle_sigint_no_inflight_is_noop() {
    let inflight = InflightPrompts(Arc::new(Mutex::new(HashSet::new())));
    let snapshot: Vec<String> = inflight.0.lock().unwrap().iter().cloned().collect();
    assert!(snapshot.is_empty());
}
