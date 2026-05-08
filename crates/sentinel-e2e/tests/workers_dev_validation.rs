//! Phase 5 plan 05-04 — VAL-02: allowlist-bleed via *.workers.dev.
//!
//! Sibling test to Phase 2's curated_deny.rs (CONTEXT C-04: do NOT extend that
//! file — the existing test must remain untouched to preserve the Phase 2
//! enforcement contract assertion shape). Reuses the same harness script
//! (crates/sentinel-e2e/harness/connect_workers_dev.js) but drives through the
//! prompt path (PTY, pre-scripted Deny) so JSONL emits via
//! prompt_channel::emit_decision_row.
//!
//! HARD assertion (CONTEXT C-04 intent, codebase-aligned shape — see
//! plan 05-04 objective for the "source_kind" rationale):
//!   - verdict = "Deny"
//!   - source_kind = "prompt_deny"   (the literal daemon emits — see 05-03 plumbing)
//!   - intel = None or absent        (the deny is from abuse-pattern, NOT a feed)
//!   - dest_host ends with ".workers.dev"
//!
//! Why these four together encode C-04's intent: a curated-allow override is
//! impossible per D-26 invariant (BuiltinDeny tier 0 always wins); a
//! feed-deny would have intel populated; only a workers.dev abuse-pattern
//! deny matches all four predicates simultaneously. The literal C-04 string
//! "builtin_deny" is never emitted by the daemon's prompt path
//! (prompt_channel.rs hardcodes "prompt_deny" for every prompt-Deny outcome
//! regardless of underlying tier), so we honor C-04 by intent rather than
//! by literal-string match.

use std::io::{BufRead, BufReader, Write as _};
use std::time::{Duration, Instant};

use portable_pty::{native_pty_system, CommandBuilder, PtySize};
use sentinel_e2e::{
    cargo_workspace_root, resolve_cli, resolve_dylib, resolve_node, DaemonHarness,
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
    let mut harness = DaemonHarness::start().expect("start daemon");

    // Reuse the Phase 2 harness script — DO NOT MODIFY IT (curated_deny.rs
    // depends on it remaining stable).
    let script = cargo_workspace_root()
        .join("crates/sentinel-e2e/harness/connect_workers_dev.js");
    assert!(
        script.exists(),
        "harness script missing at {} — Phase 2 plan 02-07 should have created it",
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
    cmd.arg(&node);
    cmd.arg(&script);
    cmd.env("HOME", harness.home.path().to_str().unwrap());
    cmd.env("PATH", std::env::var("PATH").unwrap_or_default().as_str());
    cmd.env("SENTINEL_HOOK_DYLIB", dylib.to_str().unwrap());
    cmd.env("SENTINEL_STATE_DIR", harness.state_dir.to_str().unwrap());
    // Same env vars curated_deny.rs uses — the script honors them.
    cmd.env("SENTINEL_DENY_HOST", DENY_HOST);
    cmd.env("SENTINEL_DENY_PORT", DENY_PORT);

    let mut child = pair.slave.spawn_command(cmd).expect("spawn sentinel run");
    let reader = pair.master.try_clone_reader().expect("reader");
    let mut writer = pair.master.take_writer().expect("writer");
    drop(pair.slave);

    // Wait for prompt + pre-script Deny.
    let mut br = BufReader::new(reader);
    let mut buf = String::new();
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        if Instant::now() > deadline {
            panic!(
                "prompt never appeared within 15s; PTY buf:\n{buf}\nstderr:\n{}",
                harness.drain_stderr()
            );
        }
        let mut line = String::new();
        match br.read_line(&mut line) {
            Ok(0) | Err(_) => break,
            Ok(_) => {}
        }
        buf.push_str(&line);
        if buf.contains("Choose: [1]") || buf.contains("[d]eny") || buf.contains("Deny:") {
            break;
        }
    }
    writer.write_all(b"4\n").expect("write Deny");
    drop(writer);

    let _ = child.wait();
    std::thread::sleep(Duration::from_millis(500)); // log_writer mpsc drain margin

    // -----------------------------------------------------------------------
    // HARD assertion (per C-04 intent).
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
        // attribution" which is what C-04 calls for.
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
        "VAL-02 HARD assertion failed: no JSONL row matching verdict=Deny + \
         source_kind=prompt_deny + intel=None + dest_host=*.workers.dev;\n\
         log file: {}\n\
         contents:\n{content}\n\
         daemon stderr:\n{}",
        log.display(),
        harness.drain_stderr()
    );

    drop(harness);
}
