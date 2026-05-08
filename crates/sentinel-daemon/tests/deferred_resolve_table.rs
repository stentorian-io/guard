//! Phase 3 plan 03-12 BLOCKER #3 — DeferredResolveTable unit tests.

use crossbeam_channel::bounded;
use sentinel_daemon::daemon_state::{DeferredEntry, DeferredResolveTable};

fn entry(
    run: &str,
    host: &str,
    port: u16,
) -> (
    DeferredEntry,
    crossbeam_channel::Receiver<sentinel_daemon::policy::Verdict>,
) {
    let (tx, rx) = bounded(1);
    (
        DeferredEntry {
            run_uuid: run.into(),
            host: host.into(),
            port,
            sender: tx,
            package_context: None,
        },
        rx,
    )
}

#[test]
fn insert_and_take_round_trip() {
    let table = DeferredResolveTable::new();
    let (e, rx) = entry("run-A", "example.com", 443);
    table.insert("p-1".into(), e);
    let sender = table.take("p-1").expect("present");
    let _ = sender.send(sentinel_daemon::policy::Verdict::Allow);
    assert!(matches!(
        rx.recv().unwrap(),
        sentinel_daemon::policy::Verdict::Allow
    ));
    // Second take is empty.
    assert!(table.take("p-1").is_none());
}

#[test]
fn next_prompt_id_unique() {
    let table = DeferredResolveTable::new();
    let a = table.next_prompt_id();
    let b = table.next_prompt_id();
    assert_ne!(a, b);
    assert!(a.starts_with("p-"));
}

#[test]
fn drain_for_run_signals_deny_and_removes() {
    let table = DeferredResolveTable::new();
    let mut a_rxs = Vec::new();
    let mut b_rxs = Vec::new();
    for i in 0..5u16 {
        let (e, rx) = entry("run-A", "example.com", 443 + i);
        table.insert(format!("p-A-{i}"), e);
        a_rxs.push(rx);
    }
    for i in 0..3u16 {
        let (e, rx) = entry("run-B", "other.com", 80 + i);
        table.insert(format!("p-B-{i}"), e);
        b_rxs.push(rx);
    }
    table.drain_for_run("run-A");
    // All A receivers got Deny.
    for rx in &a_rxs {
        assert!(matches!(
            rx.recv().unwrap(),
            sentinel_daemon::policy::Verdict::Deny
        ));
    }
    // B receivers still pending.
    for rx in &b_rxs {
        assert!(rx.try_recv().is_err());
    }
    // A entries gone.
    assert!(table.take("p-A-0").is_none());
    // B entries still present.
    assert!(table.take("p-B-0").is_some());
}
