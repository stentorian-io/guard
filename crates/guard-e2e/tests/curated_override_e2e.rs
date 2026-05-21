//! E2E: curated (built-in) rule disable/enable via IPC and CLI.
//!
//! Tests the full lifecycle: disable → list shows disabled → enable → list
//! shows re-enabled. CLI argument validation (--disable without --reason,
//! --disable + --enable conflict) is verified separately without a daemon.
//!
//! Biometric auth is CLI-side only, so IPC tests exercise the daemon
//! handlers directly via tagged IPC frames on the Unix socket.

use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::process::Command;
use std::time::Duration;

use guard_e2e::{DaemonHarness, resolve_cli};
use guard_ipc::frame::{read_frame, write_frame};
use guard_ipc::{
    DisableCuratedRule, DisableCuratedRuleReply, EnableCuratedRule, EnableCuratedRuleReply,
    ListRules, ListRulesReply,
};

const TAG_LIST_RULES: u8 = 0x0E;
const TAG_DISABLE_CURATED_RULE: u8 = 0x16;
const TAG_ENABLE_CURATED_RULE: u8 = 0x17;

fn send_tagged<Req: serde::Serialize, Rep: serde::de::DeserializeOwned>(
    sock: &std::path::Path,
    tag: u8,
    req: &Req,
) -> Rep {
    let mut stream = UnixStream::connect(sock).expect("connect");
    stream.set_read_timeout(Some(Duration::from_secs(5))).ok();
    stream.set_write_timeout(Some(Duration::from_secs(5))).ok();

    stream.write_all(&[tag]).expect("write tag");
    write_frame(&mut stream, req).expect("write frame");

    let mut tag_back = [0u8; 1];
    stream.read_exact(&mut tag_back).expect("read tag echo");
    assert_eq!(tag_back[0], tag, "tag mismatch");

    read_frame(&mut stream).expect("read reply")
}

// ---------------------------------------------------------------------------
// IPC-level tests (daemon required, biometric bypassed)
// ---------------------------------------------------------------------------

#[cfg(target_os = "macos")]
#[test]
fn disable_list_enable_lifecycle() {
    let harness = DaemonHarness::start().expect("start daemon");

    // "registry.npmjs.org" is in the curated allow list.
    let pattern = "registry.npmjs.org";

    // 1. Disable the curated rule.
    let req = DisableCuratedRule::new(pattern, "suspected compromise");
    let reply: DisableCuratedRuleReply =
        send_tagged(&harness.socket, TAG_DISABLE_CURATED_RULE, &req);
    assert!(
        matches!(reply, DisableCuratedRuleReply::Ok { .. }),
        "disable should succeed; got {reply:?}"
    );

    // 2. ListRules with builtins should show the rule as disabled.
    let req = ListRules::new(true);
    let reply: ListRulesReply = send_tagged(&harness.socket, TAG_LIST_RULES, &req);
    let rules = match reply {
        ListRulesReply::Ok { rules, .. } => rules,
        ListRulesReply::Err { message, .. } => panic!("list_rules failed: {message}"),
    };
    let npm_rule = rules
        .iter()
        .find(|r| r.pattern == pattern)
        .expect("npm rule should be present in list");
    assert_eq!(
        npm_rule.source, "builtin (disabled)",
        "disabled rule source should be 'builtin (disabled)'; got {:?}",
        npm_rule.source
    );

    // 3. Disable is idempotent.
    let req = DisableCuratedRule::new(pattern, "still compromised");
    let reply: DisableCuratedRuleReply =
        send_tagged(&harness.socket, TAG_DISABLE_CURATED_RULE, &req);
    assert!(
        matches!(reply, DisableCuratedRuleReply::Ok { .. }),
        "idempotent disable should succeed; got {reply:?}"
    );

    // 4. Re-enable the curated rule.
    let req = EnableCuratedRule::new(pattern);
    let reply: EnableCuratedRuleReply = send_tagged(&harness.socket, TAG_ENABLE_CURATED_RULE, &req);
    match reply {
        EnableCuratedRuleReply::Ok { was_disabled, .. } => {
            assert!(was_disabled, "should report was_disabled=true");
        }
        EnableCuratedRuleReply::Err { message, .. } => {
            panic!("enable should succeed; got err: {message}");
        }
    }

    // 5. ListRules should now show the rule as "builtin" again.
    let req = ListRules::new(true);
    let reply: ListRulesReply = send_tagged(&harness.socket, TAG_LIST_RULES, &req);
    let rules = match reply {
        ListRulesReply::Ok { rules, .. } => rules,
        ListRulesReply::Err { message, .. } => panic!("list_rules failed: {message}"),
    };
    let npm_rule = rules
        .iter()
        .find(|r| r.pattern == pattern)
        .expect("npm rule should be present after re-enable");
    assert_eq!(
        npm_rule.source, "builtin",
        "re-enabled rule source should be 'builtin'; got {:?}",
        npm_rule.source
    );

    // 6. Enable a rule that was never disabled → was_disabled=false.
    let req = EnableCuratedRule::new("pypi.org");
    let reply: EnableCuratedRuleReply = send_tagged(&harness.socket, TAG_ENABLE_CURATED_RULE, &req);
    match reply {
        EnableCuratedRuleReply::Ok { was_disabled, .. } => {
            assert!(!was_disabled, "pypi.org was never disabled");
        }
        EnableCuratedRuleReply::Err { message, .. } => {
            panic!("enable should succeed even for non-disabled; got err: {message}");
        }
    }
}

#[cfg(target_os = "macos")]
#[test]
fn disable_nonexistent_pattern_returns_error() {
    let harness = DaemonHarness::start().expect("start daemon");

    let req = DisableCuratedRule::new("nonexistent.example.com", "test reason");
    let reply: DisableCuratedRuleReply =
        send_tagged(&harness.socket, TAG_DISABLE_CURATED_RULE, &req);
    match reply {
        DisableCuratedRuleReply::Err { message, .. } => {
            assert!(
                message.contains("no curated rule"),
                "expected 'no curated rule' in error; got: {message}"
            );
        }
        _ => panic!("expected error for nonexistent pattern; got {reply:?}"),
    }
}

// ---------------------------------------------------------------------------
// CLI argument validation tests (no daemon needed)
// ---------------------------------------------------------------------------

#[cfg(target_os = "macos")]
#[test]
fn cli_disable_without_reason_exits_usage_error() {
    let cli = resolve_cli();
    let home = tempfile::tempdir().expect("tempdir");

    let output = Command::new(&cli)
        .args(["status", "rules", "--disable", "registry.npmjs.org"])
        .env_clear()
        .env("HOME", home.path())
        .env("PATH", std::env::var_os("PATH").unwrap_or_default())
        .output()
        .expect("spawn stt-guard");

    assert_ne!(
        output.status.code(),
        Some(0),
        "expected non-zero exit for --disable without --reason"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("--reason") || stderr.contains("required"),
        "expected clap error about --reason; got: {stderr}"
    );
}

#[cfg(target_os = "macos")]
#[test]
fn cli_disable_enable_conflict_rejected() {
    let cli = resolve_cli();
    let home = tempfile::tempdir().expect("tempdir");

    let output = Command::new(&cli)
        .args([
            "status",
            "rules",
            "--disable",
            "registry.npmjs.org",
            "--reason",
            "test",
            "--enable",
            "pypi.org",
        ])
        .env_clear()
        .env("HOME", home.path())
        .env("PATH", std::env::var_os("PATH").unwrap_or_default())
        .output()
        .expect("spawn stt-guard");

    assert_ne!(
        output.status.code(),
        Some(0),
        "expected non-zero exit for --disable + --enable conflict"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("--enable")
            || stderr.contains("conflict")
            || stderr.contains("cannot be used"),
        "expected clap conflict error; got: {stderr}"
    );
}

// ---------------------------------------------------------------------------
// CLI + daemon integration (IPC disable, then verify CLI output)
// ---------------------------------------------------------------------------

#[cfg(target_os = "macos")]
#[test]
fn cli_status_rules_include_built_in_shows_disabled() {
    let harness = DaemonHarness::start().expect("start daemon");
    let cli = resolve_cli();

    let pattern = "registry.npmjs.org";

    // Disable via IPC directly (bypass biometric).
    let req = DisableCuratedRule::new(pattern, "e2e test");
    let reply: DisableCuratedRuleReply =
        send_tagged(&harness.socket, TAG_DISABLE_CURATED_RULE, &req);
    assert!(matches!(reply, DisableCuratedRuleReply::Ok { .. }));

    // Run `stt-guard status rules --include-built-in` and verify output.
    let output = Command::new(&cli)
        .args(["status", "rules", "--include-built-in"])
        .env_clear()
        .env("HOME", harness.home.path())
        .env("PATH", std::env::var_os("PATH").unwrap_or_default())
        .env("STT_GUARD_STATE_DIR", &harness.state_dir)
        .output()
        .expect("stt-guard status rules");

    assert_eq!(
        output.status.code(),
        Some(0),
        "status rules should exit 0; stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("builtin (dis"),
        "output must show disabled marker for {pattern}; got:\n{stdout}"
    );
}
