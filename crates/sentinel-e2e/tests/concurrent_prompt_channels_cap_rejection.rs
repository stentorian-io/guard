//! Phase 3 plan 03-14 — R-05 cap rejection: 65th PromptChannelInit must
//! Err-Ack with the exact message `"max concurrent channels reached (64)"`.
//!
//! Locks the cap-rejection acceptance for the WARNING raised in the plan-03-12
//! review (the unit test `r05_cap_constant_is_64` only locks the constant; this
//! test exercises the dispatch arm in `ipc_server.rs::handle_prompt_channel_init`).
//!
//! Wire protocol for PromptChannelInit (mirroring PromptChannel::open in CLI):
//!   Request:  [1-byte tag 0x0A][4-byte len BE][CBOR PromptChannelInit body]
//!   Response: [1-byte tag echo 0x0A][4-byte len BE][CBOR PromptChannelInitAck body]
//!
//! Marked #[ignore]: requires running daemon + registered run_uuid + 65 open
//! file descriptors. Opt-in via:
//!   cargo test -p sentinel-e2e -- --ignored sixty_fifth_prompt_channel

use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::time::Duration;

use sentinel_ipc::{IPC_SCHEMA_V3, PromptChannelInit, PromptChannelInitAck};
use sentinel_ipc::frame::{read_frame, write_frame};

/// Tag byte for PromptChannelInit — mirrors TAG_PROMPT_CHANNEL_INIT in CLI.
const TAG_PROMPT_CHANNEL_INIT: u8 = 0x0A;

/// Open a raw PromptChannelInit exchange against the daemon socket.
///
/// Sends: [1-byte tag 0x0A][framed CBOR PromptChannelInit]
/// Reads: [1-byte tag echo][framed CBOR PromptChannelInitAck]
///
/// Returns the live stream (to hold the prompt-channel slot open) and the
/// decoded Ack. The stream is kept alive so the daemon doesn't tear down the
/// channel until the caller explicitly drops it.
fn open_prompt_channel_init(
    sock: &std::path::Path,
    run_uuid: &str,
) -> std::io::Result<(UnixStream, PromptChannelInitAck)> {
    let mut s = UnixStream::connect(sock)?;
    s.set_read_timeout(Some(Duration::from_secs(5)))?;
    s.set_write_timeout(Some(Duration::from_secs(5)))?;

    // Write tag byte + framed CBOR body.
    s.write_all(&[TAG_PROMPT_CHANNEL_INIT])
        .map_err(|e| std::io::Error::other(format!("tag write: {e}")))?;
    let init = PromptChannelInit {
        schema_version: IPC_SCHEMA_V3,
        run_uuid: run_uuid.to_string(),
    };
    write_frame(&mut s, &init)
        .map_err(|e| std::io::Error::other(format!("frame write: {e}")))?;

    // Read tag echo byte.
    let mut tag_back = [0u8; 1];
    s.read_exact(&mut tag_back)
        .map_err(|e| std::io::Error::other(format!("read tag echo: {e}")))?;
    if tag_back[0] != TAG_PROMPT_CHANNEL_INIT {
        return Err(std::io::Error::other(format!(
            "tag mismatch: expected 0x{TAG_PROMPT_CHANNEL_INIT:02x} got 0x{:02x}",
            tag_back[0]
        )));
    }

    // Read framed CBOR PromptChannelInitAck.
    let ack: PromptChannelInitAck = read_frame(&mut s)
        .map_err(|e| std::io::Error::other(format!("read ack: {e}")))?;
    Ok((s, ack))
}

/// Start a background `sentinel wrap -- /bin/sleep 600` so a run_uuid is
/// registered with the daemon. Returns the child handle (caller must kill it)
/// and the run_uuid (recovered from the manifest written by PrepareSnapshot).
fn start_background_tracked_run(
    harness: &sentinel_e2e::DaemonHarness,
) -> (std::process::Child, String) {
    let cli = sentinel_e2e::resolve_cli();
    let dylib = sentinel_e2e::resolve_dylib();
    let child = std::process::Command::new(&cli)
        .arg("wrap")
        .arg("/bin/sleep")
        .arg("600")
        .env_clear()
        .env("HOME", harness.home.path())
        .env("PATH", std::env::var_os("PATH").unwrap_or_default())
        .env("SENTINEL_HOOK_DYLIB", &dylib)
        .env("SENTINEL_STATE_DIR", &harness.state_dir)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("spawn background sentinel wrap");

    // Allow PrepareSnapshot IPC to complete and register a run record.
    std::thread::sleep(Duration::from_millis(600));

    // Recover the run_uuid from the manifest in the daemon state_dir.
    // Per plan 02-06a, per-run manifests live under state_dir/runs/<uuid>.manifest.
    let runs_dir = harness.state_dir.join("runs");
    let run_uuid = std::fs::read_dir(&runs_dir)
        .expect("read runs dir")
        .filter_map(|e| e.ok())
        .filter(|e| {
            e.path()
                .extension()
                .map(|ext| ext == "manifest")
                .unwrap_or(false)
        })
        .filter_map(|e| {
            e.path()
                .file_stem()
                .map(|s| s.to_string_lossy().to_string())
        })
        .next()
        .expect("at least one registered run_uuid in runs/");
    (child, run_uuid)
}

#[cfg(target_os = "macos")]
#[test]
#[ignore = "requires running daemon + 65 open file descriptors — opt-in via --ignored prompt_channels_cap"]
fn sixty_fifth_prompt_channel_init_is_err_acked_with_cap_message() {
    let harness = sentinel_e2e::DaemonHarness::start().expect("start daemon harness");
    let (mut bg, run_uuid) = start_background_tracked_run(&harness);
    let sock = sentinel_daemon::state_dir::socket_path(&harness.state_dir);

    // Open 64 PromptChannelInit streams; assert each Ok-Acks. Hold streams alive.
    let mut held: Vec<UnixStream> = Vec::with_capacity(64);
    for i in 0..64usize {
        let (s, ack) = open_prompt_channel_init(&sock, &run_uuid)
            .unwrap_or_else(|e| panic!("PromptChannelInit #{i} I/O failed: {e}"));
        match ack {
            PromptChannelInitAck::Ok { .. } => held.push(s),
            PromptChannelInitAck::Err { message, .. } => {
                panic!("PromptChannelInit #{i} unexpectedly Err-acked: {message}")
            }
        }
    }
    assert_eq!(held.len(), 64, "all 64 channels must Ok-Ack before cap test");

    // 65th — must Err-Ack with the cap message.
    let (_extra, ack65) = open_prompt_channel_init(&sock, &run_uuid)
        .expect("65th PromptChannelInit IPC roundtrip must not I/O-error");
    match ack65 {
        PromptChannelInitAck::Ok { .. } => {
            panic!("65th PromptChannelInit unexpectedly Ok-acked; R-05 cap not enforced")
        }
        PromptChannelInitAck::Err { message, .. } => {
            assert!(
                message.contains("max concurrent channels reached"),
                "Err message missing cap text; got: {message}"
            );
            assert!(
                message.contains("64"),
                "Err message missing cap value '64'; got: {message}"
            );
        }
    }

    // Drop one held stream — frees a slot — then verify the next Init Ok-Acks.
    drop(held.pop().expect("pop held channel"));
    std::thread::sleep(Duration::from_millis(150));
    let (_recover, ack66) = open_prompt_channel_init(&sock, &run_uuid)
        .expect("66th PromptChannelInit after slot freed");
    assert!(
        matches!(ack66, PromptChannelInitAck::Ok { .. }),
        "after freeing one slot, next Init must Ok-Ack; got: {:?}",
        ack66
    );

    // Teardown.
    let _ = bg.kill();
    let _ = bg.wait();
}
