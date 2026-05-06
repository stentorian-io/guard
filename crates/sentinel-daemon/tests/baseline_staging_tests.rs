use sentinel_daemon::baseline_staging::BaselineStaging;

#[test]
fn record_then_take_returns_entries() {
    let s = BaselineStaging::new();
    s.record_allow("run-1", "exact", "h.example.com", "baseline: 2026-05-08");
    s.record_allow("run-1", "suffix", ".example.com", "baseline: 2026-05-08");
    let taken = s.take("run-1").expect("entries");
    assert_eq!(taken.len(), 2);
    assert!(taken.iter().any(|r| r.pattern == "h.example.com"));
    assert!(taken.iter().any(|r| r.pattern == ".example.com"));
    assert!(s.take("run-1").is_none(), "second take returns None");
}

#[test]
fn record_idempotent_on_same_pattern() {
    let s = BaselineStaging::new();
    s.record_allow("run-1", "exact", "h.example.com", "first");
    s.record_allow("run-1", "exact", "h.example.com", "second");   // duplicate
    s.record_allow("run-1", "exact", "h.example.com", "third");
    let taken = s.take("run-1").expect("entries");
    assert_eq!(taken.len(), 1);
    assert_eq!(taken[0].reason, "first", "first reason wins");
}

#[test]
fn separate_runs_isolated() {
    let s = BaselineStaging::new();
    s.record_allow("run-1", "exact", "a", "r");
    s.record_allow("run-2", "exact", "b", "r");
    assert_eq!(s.peek_count("run-1"), 1);
    assert_eq!(s.peek_count("run-2"), 1);
    let t1 = s.take("run-1").unwrap();
    assert_eq!(t1.len(), 1);
    assert_eq!(s.peek_count("run-2"), 1);
}

#[test]
fn concurrent_record_safe() {
    use std::sync::Arc;
    let s = Arc::new(BaselineStaging::new());
    let mut handles = vec![];
    for t in 0..4u32 {
        let s = Arc::clone(&s);
        handles.push(std::thread::spawn(move || {
            for i in 0..50u32 {
                s.record_allow("R", "exact", &format!("h-{t}-{i}"), "test");
            }
        }));
    }
    for h in handles { h.join().unwrap(); }
    let taken = s.take("R").unwrap();
    assert_eq!(taken.len(), 200);
}
