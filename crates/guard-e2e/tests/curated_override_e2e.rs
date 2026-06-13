#![cfg(target_os = "macos")]

//! E2E: curated (built-in) rule disable/enable via IPC and CLI.
//!
//! Tests the full lifecycle: disable → list shows disabled → enable → list
//! shows re-enabled. CLI argument validation (--disable without --reason,
//! --disable + --enable conflict) is verified separately without a daemon.
//!
//! Mutable override authorization is enforced daemon-side. Direct unsigned
//! IPC must fail; the CLI path supplies the signed management authorization
//! after its biometric gate. Under the `test-signer` feature, the harness uses
//! explicit test-only signing and authentication instead of hardware.

#[cfg(target_os = "macos")]
use std::io::{Read, Write};
#[cfg(target_os = "macos")]
use std::os::unix::net::UnixStream;
#[cfg(target_os = "macos")]
use std::process::Command;
#[cfg(target_os = "macos")]
use std::time::Duration;

#[cfg(target_os = "macos")]
use guard_e2e::{DaemonHarness, resolve_cli};
#[cfg(target_os = "macos")]
use guard_ipc::frame::{read_frame, write_frame};
#[cfg(target_os = "macos")]
use guard_ipc::{
    DisableCuratedRule, DisableCuratedRuleReply, EnableCuratedRule, EnableCuratedRuleReply,
    ListRules, ListRulesReply,
};

#[cfg(target_os = "macos")]
const TAG_LIST_RULES: u8 = 0x0E;
#[cfg(target_os = "macos")]
const TAG_DISABLE_CURATED_RULE: u8 = 0x16;
#[cfg(target_os = "macos")]
const TAG_ENABLE_CURATED_RULE: u8 = 0x17;

#[cfg(target_os = "macos")]
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
// IPC-level tests (daemon required)
// ---------------------------------------------------------------------------

#[cfg(target_os = "macos")]
#[test]
fn direct_unsigned_disable_and_enable_are_rejected() {
    let harness = DaemonHarness::start().expect("start daemon");

    let pattern = "registry.npmjs.org";

    let req = DisableCuratedRule::new(pattern, "suspected compromise");
    let reply: DisableCuratedRuleReply =
        send_tagged(&harness.socket, TAG_DISABLE_CURATED_RULE, &req);
    match reply {
        DisableCuratedRuleReply::Err { message, .. } => assert!(
            message.contains("signed management authorization required"),
            "expected authorization failure; got: {message}"
        ),
        DisableCuratedRuleReply::Ok { .. } => {
            panic!("unsigned direct disable should fail; got {reply:?}");
        }
    }

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
        npm_rule.source, "builtin",
        "unsigned disable must not mutate state; got {:?}",
        npm_rule.source
    );

    let req = EnableCuratedRule::new(pattern);
    let reply: EnableCuratedRuleReply = send_tagged(&harness.socket, TAG_ENABLE_CURATED_RULE, &req);
    match reply {
        EnableCuratedRuleReply::Err { message, .. } => assert!(
            message.contains("signed management authorization required"),
            "expected authorization failure; got: {message}"
        ),
        EnableCuratedRuleReply::Ok { .. } => {
            panic!("unsigned direct enable should fail; got {reply:?}");
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
        DisableCuratedRuleReply::Ok { .. } => {
            panic!("expected error for nonexistent pattern; got {reply:?}");
        }
    }
}

#[cfg(all(target_os = "macos", feature = "test-signer"))]
#[test]
fn cli_signed_disable_list_enable_lifecycle_still_works() {
    let harness = DaemonHarness::start().expect("start daemon");
    let cli = resolve_cli();
    let pattern = "registry.npmjs.org";

    let disable = Command::new(&cli)
        .args([
            "status",
            "rules",
            "--disable",
            pattern,
            "--reason",
            "suspected compromise",
        ])
        .env_clear()
        .env("HOME", harness.home.path())
        .env("PATH", std::env::var_os("PATH").unwrap_or_default())
        .env("STT_GUARD_STATE_DIR", &harness.state_dir)
        .output()
        .expect("stt-guard status rules --disable");
    assert_eq!(
        disable.status.code(),
        Some(0),
        "disable should exit 0; stderr: {}",
        String::from_utf8_lossy(&disable.stderr)
    );

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
    assert_eq!(npm_rule.source, "builtin (disabled)");

    let enable = Command::new(&cli)
        .args(["status", "rules", "--enable", pattern])
        .env_clear()
        .env("HOME", harness.home.path())
        .env("PATH", std::env::var_os("PATH").unwrap_or_default())
        .env("STT_GUARD_STATE_DIR", &harness.state_dir)
        .output()
        .expect("stt-guard status rules --enable");
    assert_eq!(
        enable.status.code(),
        Some(0),
        "enable should exit 0; stderr: {}",
        String::from_utf8_lossy(&enable.stderr)
    );

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
    assert_eq!(npm_rule.source, "builtin");
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

#[cfg(all(target_os = "macos", feature = "test-signer"))]
#[test]
fn cli_status_rules_include_built_in_shows_disabled() {
    let harness = DaemonHarness::start().expect("start daemon");
    let cli = resolve_cli();

    let pattern = "registry.npmjs.org";

    let disable = Command::new(&cli)
        .args([
            "status",
            "rules",
            "--disable",
            pattern,
            "--reason",
            "e2e test",
        ])
        .env_clear()
        .env("HOME", harness.home.path())
        .env("PATH", std::env::var_os("PATH").unwrap_or_default())
        .env("STT_GUARD_STATE_DIR", &harness.state_dir)
        .output()
        .expect("stt-guard status rules --disable");
    assert_eq!(
        disable.status.code(),
        Some(0),
        "disable should exit 0; stderr: {}",
        String::from_utf8_lossy(&disable.stderr)
    );

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
