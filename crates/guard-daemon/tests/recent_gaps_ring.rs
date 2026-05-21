use guard_daemon::prompt::RecentGapsRing;
use guard_ipc::GapInfo;

fn gap(seq: u64) -> GapInfo {
    GapInfo {
        run_uuid: format!("run-{seq}"),
        gap_kind: "hardened-runtime".into(),
        binary_path: None,
        detected_at_ms: seq,
    }
}

#[test]
fn empty_then_push_then_snapshot() {
    let r = RecentGapsRing::new();
    assert!(r.is_empty());
    r.push(gap(1));
    let s = r.snapshot();
    assert_eq!(s.len(), 1);
    assert_eq!(s[0].run_uuid, "run-1");
}

#[test]
fn push_under_capacity_preserves_all() {
    let r = RecentGapsRing::new();
    for i in 0..50 {
        r.push(gap(i));
    }
    assert_eq!(r.len(), 50);
    let s = r.snapshot();
    assert_eq!(s.first().unwrap().run_uuid, "run-0");
    assert_eq!(s.last().unwrap().run_uuid, "run-49");
}

#[test]
fn push_over_capacity_evicts_oldest_first() {
    let r = RecentGapsRing::new();
    for i in 0..150 {
        r.push(gap(i));
    }
    assert_eq!(r.len(), 100);
    let s = r.snapshot();
    // Oldest survivor: run-50 (entries 0..49 evicted).
    assert_eq!(s.first().unwrap().run_uuid, "run-50");
    assert_eq!(s.last().unwrap().run_uuid, "run-149");
}

#[test]
fn concurrent_push_safe() {
    use std::sync::Arc;
    let r = Arc::new(RecentGapsRing::new());
    let mut handles = vec![];
    for t in 0..4u64 {
        let r = Arc::clone(&r);
        handles.push(std::thread::spawn(move || {
            for i in 0..100u64 {
                r.push(gap(t * 1000 + i));
            }
        }));
    }
    for h in handles {
        h.join().unwrap();
    }
    // Total pushes = 400; ring caps at 100; no panics.
    assert_eq!(r.len(), 100);
}
