//! Render smoke tests for status output.

use sentinel_ipc::{DaemonStateKind, FeedInfo, StatusCounters};

fn empty_counters() -> StatusCounters {
    StatusCounters {
        rules_user: 0,
        rules_trusted_toml: 0,
        blocks_today: 0,
        allows_today: 0,
        gaps_today: 0,
    }
}

#[test]
fn render_minimal_operational() {
    let mut buf = Vec::new();
    sentinel_cli::status::render_minimal_to(&mut buf, DaemonStateKind::Operational, 0, &[]);
    let s = String::from_utf8(buf).unwrap();
    assert!(s.contains("operational"), "got: {s}");
}

#[test]
fn render_minimal_degraded_shows_gap_count() {
    let mut buf = Vec::new();
    sentinel_cli::status::render_minimal_to(&mut buf, DaemonStateKind::Degraded, 3, &[]);
    let s = String::from_utf8(buf).unwrap();
    assert!(s.contains("degraded"), "got: {s}");
    assert!(s.contains("3 coverage gap"), "got: {s}");
}

#[test]
fn render_verbose_includes_state_line() {
    let mut buf = Vec::new();
    sentinel_cli::status::render_verbose_to(
        &mut buf,
        DaemonStateKind::Operational,
        &[],
        &[],
        &empty_counters(),
        &[],
        None,
    );
    let s = String::from_utf8(buf).unwrap();
    assert!(s.starts_with("State: operational"), "got: {s}");
}

#[test]
fn render_minimal_stale_feeds_names() {
    let feeds = vec![
        FeedInfo { name: "OSV".to_string(), last_pulled_at_ms: Some(100), fresh: false },
        FeedInfo { name: "GHSA".to_string(), last_pulled_at_ms: Some(200), fresh: true },
    ];
    let mut buf = Vec::new();
    sentinel_cli::status::render_minimal_to(&mut buf, DaemonStateKind::StaleFeeds, 0, &feeds);
    let s = String::from_utf8(buf).unwrap();
    assert!(s.contains("OSV"), "should mention stale feed: {s}");
    assert!(!s.contains("GHSA"), "should not mention fresh feed: {s}");
}
