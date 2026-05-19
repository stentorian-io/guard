//! v0.5 — allowlist-bleed via *.workers.dev.
//!
//! Sibling test to v0.2's curated_deny.rs (do NOT extend that
//! file — the existing test must remain untouched to preserve the v0.2
//! enforcement contract assertion shape). Reuses the same harness script
//! (crates/sentinel-e2e/harness/connect_workers_dev.js) but drives through the
//! prompt path (PTY, pre-scripted Deny) so JSONL emits via
//! prompt_channel::emit_decision_row.
//!
//! HARD assertion (codebase-aligned shape):
//!   - verdict = "Deny"
//!   - source_kind = "prompt_deny"   (the literal daemon emits — see 05-03 plumbing)
//!   - intel = None or absent        (the deny is from abuse-pattern, NOT a feed)
//!   - dest_host ends with ".workers.dev"
//!
//! Why these four together encode the intent: a curated-allow override is
//! impossible per D-26 invariant (BuiltinDeny tier 0 always wins); a
//! feed-deny would have intel populated; only a workers.dev abuse-pattern
//! deny matches all four predicates simultaneously. The literal
//! "builtin_deny" is never emitted by the daemon's prompt path
//! (prompt_channel.rs hardcodes "prompt_deny" for every prompt-Deny outcome
//! regardless of underlying tier), so we honor the intent rather than a
//! literal-string match.

use std::io::Write as _;
use std::time::Duration;

use portable_pty::{CommandBuilder, PtySize, native_pty_system};
use sentinel_e2e::{
    DaemonHarness, cargo_workspace_root, prepare_feed_fixture, read_pty_until, resolve_cli,
    resolve_dylib, resolve_node,
};

const DENY_HOST: &str = "exfil.workers.dev";
const DENY_PORT: &str = "443";

#[cfg_attr(not(target_os = "macos"), ignore)]
#[test]
fn workers_dev_deny_emits_jsonl_with_prompt_deny_and_no_intel() {
    let cli = resolve_cli();
    let dylib = resolve_dylib();
    let node = match resolve_node() {
        Ok(p) => p,
        Err(why) => {
            eprintln!("SKIP workers_dev_validation: {why}");
            return;
        }
    };
    // Use a local file:// feed fixture instead of DaemonHarness::start()'s
    // default SENTINEL_SKIP_FEED_FETCH=1 (which is compiled out in --release
    // builds, causing CI to attempt a real GitHub clone that times out).
    let (_feed_dir, feed_url) = prepare_feed_fixture("feed-mock-ua-parser-js");
    let mut harness = DaemonHarness::start_with_env(&[
        ("SENTINEL_FEED_URL_OVERRIDE_OSV", feed_url.as_str()),
        ("SENTINEL_FEED_URL_OVERRIDE_GHSA", feed_url.as_str()),
    ])
    .expect("start daemon");

    // Reuse the v0.2 harness script — DO NOT MODIFY IT (curated_deny.rs
    // depends on it remaining stable).
    let script = cargo_workspace_root().join("crates/sentinel-e2e/harness/connect_workers_dev.js");
    assert!(
        script.exists(),
        "harness script missing at {} — v0.2 should have created it",
        script.display()
    );

    // -----------------------------------------------------------------------
    // PTY scaffolding (from prompt_unblock_deny.rs).
    // -----------------------------------------------------------------------
    let pty_system = native_pty_system();
    let pair = pty_system
        .openpty(PtySize {
            rows: 24,
            cols: 80,
            pixel_width: 0,
            pixel_height: 0,
        })
        .expect("openpty");

    let mut cmd = CommandBuilder::new(&cli);
    cmd.arg("wrap");
    cmd.arg(&node);
    cmd.arg(&script);
    cmd.env("HOME", harness.home.path().to_str().unwrap());
    cmd.env("PATH", std::env::var("PATH").unwrap_or_default().as_str());
    cmd.env("SENTINEL_HOOK_DYLIB", dylib.to_str().unwrap());
    cmd.env("SENTINEL_STATE_DIR", harness.state_dir.to_str().unwrap());
    // Same env vars curated_deny.rs uses — the script honors them.
    cmd.env("SENTINEL_TEST_DENY_HOST", DENY_HOST);
    cmd.env("SENTINEL_TEST_DENY_PORT", DENY_PORT);

    let mut child = pair.slave.spawn_command(cmd).expect("spawn sentinel wrap");
    let reader = pair.master.try_clone_reader().expect("reader");
    let mut writer = pair.master.take_writer().expect("writer");
    drop(pair.slave);

    // Wait for prompt + pre-script Deny.
    let _buf = read_pty_until(reader, "Choose: [1]", Duration::from_secs(15))
        .unwrap_or_else(|e| panic!("{e}\nstderr:\n{}", harness.drain_stderr()));
    writer.write_all(b"3\n").expect("write Deny");
    drop(writer);

    let _ = child.wait();
    std::thread::sleep(Duration::from_millis(500)); // log_writer mpsc drain margin

    // -----------------------------------------------------------------------
    // HARD assertion.
    // -----------------------------------------------------------------------
    let log = harness
        .home
        .path()
        .join("Library/Logs/Sentinel/sentinel.log");
    let content = std::fs::read_to_string(&log).unwrap_or_default();
    let matched = content.lines().any(|line| {
        let v: serde_json::Value = match serde_json::from_str(line) {
            Ok(v) => v,
            Err(_) => return false,
        };
        let verdict = v.get("verdict").and_then(|x| x.as_str());
        let source_kind = v.get("source_kind").and_then(|x| x.as_str());
        let host = v.get("dest_host").and_then(|x| x.as_str()).unwrap_or("");
        // intel: either field absent (None at serialization via
        // skip_serializing_if) or explicit JSON null. Both indicate "no feed
        // attribution" which is what the intent calls for.
        let intel_field = v.get("intel");
        let intel_is_none = match intel_field {
            None => true,
            Some(serde_json::Value::Null) => true,
            _ => false,
        };
        verdict == Some("Deny")
            && source_kind == Some("prompt_deny")
            && intel_is_none
            && host.ends_with(".workers.dev")
    });
    assert!(
        matched,
        "HARD assertion failed: no JSONL row matching verdict=Deny + \
         source_kind=prompt_deny + intel=None + dest_host=*.workers.dev;\n\
         log file: {}\n\
         contents:\n{content}\n\
         daemon stderr:\n{}",
        log.display(),
        harness.drain_stderr()
    );

    drop(harness);
}
