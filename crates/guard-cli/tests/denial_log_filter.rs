//! v0.3 — `denial_log` block-destination filter unit tests.
//!
//! v0.7 — the parser moved from `approve` to `denial_log`; file renamed from
//! `approve_from_log_filter.rs` to `denial_log_filter.rs` so the test path
//! matches the module under test.
use guard_cli::denial_log::{BlockEntry, filter_block_destinations};

#[test]
fn filter_keeps_only_matching_run_uuid_block_events() {
    let dir = tempfile::tempdir().unwrap();
    let log = dir.path().join("stt-guard.log");
    let lines = [
        // run X — block
        r#"{"event":"block","run_uuid":"X","dest_host":"a.example.com","dest_port":443,"source_kind":"default_deny"}"#,
        // run X — allow (skipped)
        r#"{"event":"allow","run_uuid":"X","dest_host":"b.example.com","dest_port":443,"source_kind":"prompt_allow_once"}"#,
        // run Y — block (different run, skipped)
        r#"{"event":"block","run_uuid":"Y","dest_host":"c.example.com","dest_port":443,"source_kind":"default_deny"}"#,
        // run X — block (duplicate host:port — dedup)
        r#"{"event":"block","run_uuid":"X","dest_host":"a.example.com","dest_port":443,"source_kind":"default_deny"}"#,
        // run X — gap (skipped)
        r#"{"event":"gap","run_uuid":"X","gap_kind":"hardened-runtime"}"#,
        // run X — block, different port (kept)
        r#"{"event":"block","run_uuid":"X","dest_host":"a.example.com","dest_port":80,"source_kind":"default_deny"}"#,
    ];
    std::fs::write(&log, lines.join("\n")).unwrap();
    let blocks = filter_block_destinations(&log, "X").unwrap();
    assert_eq!(blocks.len(), 2);
    assert!(
        blocks
            .iter()
            .any(|b: &BlockEntry| b.host == "a.example.com" && b.port == 443)
    );
    assert!(
        blocks
            .iter()
            .any(|b: &BlockEntry| b.host == "a.example.com" && b.port == 80)
    );
}

#[test]
fn filter_returns_empty_when_no_match() {
    let dir = tempfile::tempdir().unwrap();
    let log = dir.path().join("stt-guard.log");
    std::fs::write(&log, r#"{"event":"block","run_uuid":"Z","dest_host":"x"}"#).unwrap();
    let blocks = filter_block_destinations(&log, "X").unwrap();
    assert!(blocks.is_empty());
}

#[test]
fn missing_log_file_returns_clear_error() {
    let dir = tempfile::tempdir().unwrap();
    let log = dir.path().join("nonexistent.log");
    let r = filter_block_destinations(&log, "X");
    assert!(r.is_err());
}
