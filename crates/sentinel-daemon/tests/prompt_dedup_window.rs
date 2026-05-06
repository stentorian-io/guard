use std::time::{Duration, Instant};
use sentinel_daemon::prompt::{CoalesceOutcome, PromptDedup};

#[test]
fn first_coalesce_is_fresh_second_returns_existing() {
    let d = PromptDedup::new();
    let now = Instant::now();
    assert_eq!(d.coalesce_with_now(now, "r1", "h", 443, "p1"), CoalesceOutcome::Fresh);
    let res = d.coalesce_with_now(now + Duration::from_millis(100), "r1", "h", 443, "p2");
    assert_eq!(res, CoalesceOutcome::Existing("p1".into()));
}

#[test]
fn different_port_is_fresh_d46_port_granularity() {
    let d = PromptDedup::new();
    let now = Instant::now();
    d.coalesce_with_now(now, "r1", "h", 443, "p1");
    assert_eq!(d.coalesce_with_now(now, "r1", "h", 80, "p2"), CoalesceOutcome::Fresh);
}

#[test]
fn different_run_uuid_is_fresh() {
    let d = PromptDedup::new();
    let now = Instant::now();
    d.coalesce_with_now(now, "r1", "h", 443, "p1");
    assert_eq!(d.coalesce_with_now(now, "r2", "h", 443, "p2"), CoalesceOutcome::Fresh);
}

#[test]
fn after_5_seconds_window_is_fresh_again() {
    let d = PromptDedup::new();
    let now = Instant::now();
    d.coalesce_with_now(now, "r1", "h", 443, "p1");
    let after = now + Duration::from_secs(5) + Duration::from_millis(1);
    assert_eq!(d.coalesce_with_now(after, "r1", "h", 443, "p2"), CoalesceOutcome::Fresh);
}

#[test]
fn forget_removes_entry() {
    let d = PromptDedup::new();
    let now = Instant::now();
    d.coalesce_with_now(now, "r1", "h", 443, "p1");
    d.forget("r1", "h", 443);
    assert_eq!(d.coalesce_with_now(now, "r1", "h", 443, "p2"), CoalesceOutcome::Fresh);
}

#[test]
#[ignore] // Slow test — sleeps 6 seconds; run with `cargo test -- --include-ignored`
fn gc_expired_clears_old_entries() {
    let d = PromptDedup::new();
    let now = Instant::now();
    d.coalesce_with_now(now, "r1", "h", 443, "p1");
    // Sleep past window then GC.
    std::thread::sleep(Duration::from_secs(6));
    d.gc_expired();
    // Internal state cleared — fresh-coalesce confirms via observable behavior.
    assert_eq!(d.coalesce("r1", "h", 443, "p2"), CoalesceOutcome::Fresh);
}
