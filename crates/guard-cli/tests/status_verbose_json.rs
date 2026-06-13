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
        Some(&guard_ipc::SigningInfo {
            configured: true,
            status: "configured".to_string(),
            signer_kind: Some("macos-keychain".to_string()),
            fingerprint: Some("00112233445566778899aabbccddeeff".to_string()),
            trust_root_path: Some(
                "/usr/local/libexec/stt-guard/trusted-rule-signers.tsv".to_string(),
            ),
            trust_root_ok: true,
            reason: None,
            action: None,
        }),
    );
    let s = String::from_utf8(buf).unwrap();
    assert!(s.contains("State: operational"));
    assert!(s.contains("rules_user:   3"));
    assert!(s.contains("blocks_today: 1"));
    assert!(s.contains("Signing:"));
    assert!(s.contains("OS-backed: configured"));
    assert!(s.contains("signer kind: macos-keychain"));
}
