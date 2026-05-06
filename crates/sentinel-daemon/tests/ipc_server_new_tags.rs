//! Phase 3 plan 03-08: smoke test that ipc_server dispatches new tags 0x09..0x0D.
//! Full IPC integration coverage in plan 03-14 e2e.
//!
//! Tag bytes 0x09..0x0D were added in plan 03-02 (MessageTag enum).
//! This test verifies they resolve correctly via MessageTag::from_byte.

use sentinel_daemon::ipc_dispatch::MessageTag;

#[test]
fn all_phase3_tags_resolve() {
    assert!(matches!(
        MessageTag::from_byte(0x09),
        Some(MessageTag::Status)
    ));
    assert!(matches!(
        MessageTag::from_byte(0x0A),
        Some(MessageTag::PromptChannelInit)
    ));
    assert!(matches!(
        MessageTag::from_byte(0x0B),
        Some(MessageTag::InsertUserRule)
    ));
    assert!(matches!(
        MessageTag::from_byte(0x0C),
        Some(MessageTag::ReadInstallArtifacts)
    ));
    assert!(matches!(
        MessageTag::from_byte(0x0D),
        Some(MessageTag::BaselineCommit)
    ));
}
