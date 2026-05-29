//! v0.5 — allowlist-bleed via *.workers.dev.
//!
//! Sibling test to v0.2's `curated_deny.rs` (do NOT extend that
//! file — the existing test must remain untouched to preserve the v0.2
//! enforcement contract assertion shape).
//!
//! The `.workers.dev` suffix rule in `malicious-curated.yaml` has tier `BuiltinDeny`
//! (Tier 0, non-overridable per D-26). The daemon's Resolve handler evaluates
//! policy BEFORE prompting — `BuiltinDeny` denies without prompting and emits
//! a JSONL row directly.
//!
//! HARD assertion (codebase-aligned shape):
//!   - verdict = "Deny"
//!   - `source_kind` = "builtin-deny"  (non-promptable, direct policy deny)
//!   - intel = None or absent        (the deny is from abuse-pattern, NOT a feed)
//!   - `dest_host` ends with ".workers.dev"

use std::process::Command;

use guard_e2e::{DaemonHarness, cargo_workspace_root, resolve_cli, resolve_dylib, resolve_node};

const DENY_HOST: &str = "exfil.workers.dev";
const DENY_PORT: &str = "443";

#[cfg_attr(not(target_os = "macos"), ignore = "macOS-only test")]
#[test]
fn workers_dev_deny_emits_jsonl_with_builtin_deny_and_no_intel() {
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

    let script = cargo_workspace_root().join("crates/guard-e2e/harness/connect_workers_dev.js");
    assert!(
        script.exists(),
        "harness script missing at {} — v0.2 should have created it",
        script.display()
    );

    let output = Command::new(&cli)
        .arg("wrap")
        .arg(&node)
        .arg(&script)
        .env_clear()
        .env("HOME", harness.home.path())
        .env("PATH", std::env::var_os("PATH").unwrap_or_default())
        .env("STT_GUARD_HOOK_DYLIB", &dylib)
        .env("STT_GUARD_STATE_DIR", &harness.state_dir)
        .env("STT_GUARD_TEST_DENY_HOST", DENY_HOST)
        .env("STT_GUARD_TEST_DENY_PORT", DENY_PORT)
        .output()
        .expect("run stt-guard");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(
        !output.status.success(),
        "ALLOW-06 violation: wrapped node exited 0 (workers.dev not denied?)\n\
         host: {DENY_HOST}:{DENY_PORT}\nstdout: {stdout}\nstderr: {stderr}"
    );

    let code = output.status.code().unwrap_or(-1);
    assert_eq!(
        code, 1,
        "expected exit 1 (Stentorian Guard-deny errno class); got {code}\n\
         stdout: {stdout}\nstderr: {stderr}"
    );

    assert!(
        stdout.contains("CONNECT-FAILED"),
        "expected CONNECT-FAILED in script stdout; got: {stdout}"
    );

    // log_writer mpsc drain margin
    std::thread::sleep(std::time::Duration::from_millis(500));

    // -----------------------------------------------------------------------
    // HARD assertion: JSONL row from the BuiltinDeny resolve-gate path.
    // -----------------------------------------------------------------------
    let log = harness
        .home
        .path()
        .join("Library/Logs/Stentorian Guard/stt-guard.log");
    let content = std::fs::read_to_string(&log).unwrap_or_default();
    let matched = content.lines().any(|line| {
        let v: serde_json::Value = match serde_json::from_str(line) {
            Ok(v) => v,
            Err(_) => return false,
        };
        let verdict = v.get("verdict").and_then(|x| x.as_str());
        let source_kind = v.get("source_kind").and_then(|x| x.as_str());
        let host = v.get("dest_host").and_then(|x| x.as_str()).unwrap_or("");
        let intel_field = v.get("intel");
        let intel_is_none = matches!(intel_field, None | Some(serde_json::Value::Null));
        verdict == Some("Deny")
            && source_kind == Some("builtin-deny")
            && intel_is_none
            && host.ends_with(".workers.dev")
    });
    assert!(
        matched,
        "HARD assertion failed: no JSONL row matching verdict=Deny + \
         source_kind=builtin-deny + intel=None + dest_host=*.workers.dev;\n\
         log file: {}\n\
         contents:\n{content}\n\
         daemon stderr:\n{}",
        log.display(),
        harness.drain_stderr()
    );

    drop(harness);
}
