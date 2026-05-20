//! Render smoke tests for status output.

use sentinel_ipc::{DaemonStateKind, StatusCounters};

fn empty_counters() -> StatusCounters {
    StatusCounters {
        rules_user: 0,
        blocks_today: 0,
        allows_today: 0,
        gaps_today: 0,
    }
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
        None,
    );
    let s = String::from_utf8(buf).unwrap();
    assert!(s.starts_with("State: operational"), "got: {s}");
}
