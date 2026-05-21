//! Verify that status render functions produce valid output.

use guard_ipc::{DaemonStateKind, StatusCounters};

#[test]
fn verbose_render_produces_output() {
    let counters = StatusCounters {
        rules_user: 3,
        blocks_today: 1,
        allows_today: 10,
        gaps_today: 0,
    };
    let mut buf = Vec::new();
    guard_cli::status::render_verbose_to(
        &mut buf,
        DaemonStateKind::Operational,
        &[],
        &[],
        &counters,
        None,
    );
    let s = String::from_utf8(buf).unwrap();
    assert!(s.contains("State: operational"));
    assert!(s.contains("rules_user:   3"));
    assert!(s.contains("blocks_today: 1"));
}
