use sentinel_core::AuditToken;
use sentinel_daemon::gap_detector::{GapDetector, GAP_TIMEOUT_MS};
use sentinel_daemon::tracked::{CoverageGap, ProcessTree};
use std::sync::Arc;
use std::time::Duration;

fn token(pid: u32) -> AuditToken {
    AuditToken { val: [0, 0, 0, 0, 0, pid, 0, 0] }
}

fn pending_gap() -> CoverageGap {
    CoverageGap::ConfirmedHardened {
        binary_path: "/usr/bin/python3".into(),
        detected_at_ms: 0,
    }
}

fn build_tree(t: AuditToken) -> Arc<ProcessTree> {
    let tree = Arc::new(ProcessTree::new());
    tree.insert_root(t, "u1".into(), "/usr/bin/npm".into());
    tree
}

#[test]
fn timeout_const_is_500() {
    assert_eq!(GAP_TIMEOUT_MS, 500);
}

#[test]
fn timeout_fires_records_gap() {
    let t = token(100);
    let tree = build_tree(t);
    let det = GapDetector::new();
    det.arm(t, pending_gap(), tree.clone());
    // Wait for the timer to fire (500ms + small slack).
    std::thread::sleep(Duration::from_millis(GAP_TIMEOUT_MS + 200));
    let n = tree.get_node(&t).expect("node");
    assert!(n.coverage_gap.is_some(), "gap should be recorded after timeout");
}

#[test]
fn cancel_before_timeout_prevents_gap() {
    let t = token(101);
    let tree = build_tree(t);
    let det = GapDetector::new();
    det.arm(t, pending_gap(), tree.clone());
    std::thread::sleep(Duration::from_millis(50));
    assert!(det.cancel(&t), "cancel should return true (pending timer existed)");
    std::thread::sleep(Duration::from_millis(GAP_TIMEOUT_MS + 200));
    let n = tree.get_node(&t).expect("node");
    assert!(n.coverage_gap.is_none(), "no gap recorded when cancelled in time");
}

#[test]
fn cancel_returns_false_for_unknown_token() {
    let det = GapDetector::new();
    let unknown = token(999);
    assert!(!det.cancel(&unknown));
}

#[test]
fn re_arming_replaces_prior_timer() {
    let t = token(102);
    let tree = build_tree(t);
    let det = GapDetector::new();
    det.arm(t, pending_gap(), tree.clone());
    // Re-arm immediately with a different gap so we can tell the new one fired.
    let gap2 = CoverageGap::UnknownInjectionFailure {
        binary_path: "/usr/bin/sshd".into(),
        detected_at_ms: 0,
    };
    det.arm(t, gap2.clone(), tree.clone());
    std::thread::sleep(Duration::from_millis(GAP_TIMEOUT_MS + 200));
    let n = tree.get_node(&t).unwrap();
    match n.coverage_gap.expect("gap") {
        CoverageGap::UnknownInjectionFailure { binary_path, .. } => {
            assert_eq!(binary_path, "/usr/bin/sshd");
        }
        other => panic!("expected UnknownInjectionFailure, got {other:?}"),
    }
}

#[test]
fn many_concurrent_arms_each_complete() {
    let tree = Arc::new(ProcessTree::new());
    for i in 0..32 {
        let t = token(1000 + i);
        tree.insert_root(t, "u1".into(), "/x".into());
    }
    let det = GapDetector::new();
    for i in 0..32 {
        det.arm(token(1000 + i), pending_gap(), tree.clone());
    }
    std::thread::sleep(Duration::from_millis(GAP_TIMEOUT_MS + 300));
    let mut count_with_gap = 0;
    for i in 0..32 {
        if tree.get_node(&token(1000 + i)).unwrap().coverage_gap.is_some() {
            count_with_gap += 1;
        }
    }
    assert_eq!(count_with_gap, 32, "all 32 timers should have fired and recorded gaps");
}
