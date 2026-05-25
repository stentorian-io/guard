//! v0.3 — channel frame round-trip + cap unit smoke.

use crossbeam_channel::bounded;
use guard_daemon::handlers::prompt_channel::{ClientChannelFrame, MAX_CONCURRENT_CHANNELS};
use guard_daemon::tracked::ProcessTree;
use guard_ipc::{IPC_SCHEMA_V3, PromptCancel, PromptResponse, PromptVerdict};

#[test]
fn channel_frame_round_trip() {
    let r = ClientChannelFrame::Response(PromptResponse {
        schema_version: IPC_SCHEMA_V3,
        prompt_id: "p1".into(),
        verdict: PromptVerdict::AllowOnce,
        rule_pattern: None,
        signed_rule: None,
    });
    let mut bytes = Vec::new();
    ciborium::into_writer(&r, &mut bytes).unwrap();
    let decoded: ClientChannelFrame = ciborium::from_reader(bytes.as_slice()).unwrap();
    if let ClientChannelFrame::Response(d) = decoded {
        assert_eq!(d.prompt_id, "p1");
    } else {
        panic!("expected Response");
    }

    let c = ClientChannelFrame::Cancel(PromptCancel {
        schema_version: IPC_SCHEMA_V3,
        prompt_id: "p2".into(),
    });
    let mut bytes = Vec::new();
    ciborium::into_writer(&c, &mut bytes).unwrap();
    let decoded: ClientChannelFrame = ciborium::from_reader(bytes.as_slice()).unwrap();
    if let ClientChannelFrame::Cancel(d) = decoded {
        assert_eq!(d.prompt_id, "p2");
    } else {
        panic!("expected Cancel");
    }
}

#[test]
fn process_tree_prompt_channels_len_tracks_inserts() {
    let tree = ProcessTree::new();
    assert_eq!(tree.prompt_channels_len(), 0);
    let mut keepalive = Vec::new();
    for i in 0..10 {
        let (tx, rx) = bounded::<guard_ipc::PromptRequest>(1);
        keepalive.push(rx);
        tree.set_prompt_channel(&format!("run-{i}"), tx);
    }
    assert_eq!(tree.prompt_channels_len(), 10);
    let _ = tree.take_prompt_channel("run-0");
    assert_eq!(tree.prompt_channels_len(), 9);
}

#[test]
fn r05_cap_constant_is_64() {
    // Locks the cap value for the integration test (it asserts the
    // 65th PromptChannelInit Err-Acks with this exact reason format).
    assert_eq!(MAX_CONCURRENT_CHANNELS, 64);
}
