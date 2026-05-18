use clap::Parser;
use sentinel_cli::cli::{Cli, Cmd, StatusSub};
use std::ffi::OsString;

// ---- sentinel wrap parser shape -----------------------------------------------

#[test]
fn wrap_with_simple_command() {
    let cli = Cli::try_parse_from(["sentinel", "wrap", "echo", "hello"]).expect("parse");
    match cli.cmd {
        Cmd::Wrap { learn, argv } => {
            assert!(!learn);
            assert_eq!(argv, vec![OsString::from("echo"), OsString::from("hello")]);
        }
        other => panic!("expected Wrap variant, got {other:?}"),
    }
}

#[test]
fn wrap_preserves_hyphen_args_in_wrapped_command() {
    let cli = Cli::try_parse_from(
        ["sentinel", "wrap", "node", "-e", "console.log(1)"]
    ).expect("parse");
    match cli.cmd {
        Cmd::Wrap { learn, argv } => {
            assert!(!learn);
            assert_eq!(argv, vec![
                OsString::from("node"),
                OsString::from("-e"),
                OsString::from("console.log(1)"),
            ]);
        }
        other => panic!("expected Wrap variant, got {other:?}"),
    }
}

#[test]
fn wrap_with_help_flag_routes_to_child() {
    let cli = Cli::try_parse_from(["sentinel", "wrap", "echo", "--help"]).expect("parse");
    match cli.cmd {
        Cmd::Wrap { argv, .. } => {
            assert_eq!(argv, vec![
                OsString::from("echo"),
                OsString::from("--help"),
            ]);
        }
        other => panic!("expected Wrap variant, got {other:?}"),
    }
}

// ---- --learn flag on wrap ----------------------------------------------------

#[test]
fn learn_flag_on_wrap_subcommand() {
    let cli = Cli::try_parse_from(["sentinel", "wrap", "--learn", "npm", "install"]).expect("parse");
    match cli.cmd {
        Cmd::Wrap { learn, argv } => {
            assert!(learn);
            assert_eq!(argv, vec![OsString::from("npm"), OsString::from("install")]);
        }
        other => panic!("expected Wrap variant, got {other:?}"),
    }
}

#[test]
fn learn_after_wrapped_command_is_a_child_arg() {
    let cli = Cli::try_parse_from(["sentinel", "wrap", "npm", "install", "--learn"]).expect("parse");
    match cli.cmd {
        Cmd::Wrap { learn, argv } => {
            assert!(!learn, "--learn after the wrapped command must NOT set learn flag");
            assert_eq!(argv.last().unwrap(), &OsString::from("--learn"));
            assert_eq!(argv.len(), 3);
        }
        other => panic!("expected Wrap variant, got {other:?}"),
    }
}

// ---- Negative tests --------------------------------------------------------

#[test]
fn bare_sentinel_no_args_is_parse_error() {
    let r = Cli::try_parse_from(["sentinel"]);
    assert!(r.is_err(), "bare sentinel with no subcommand must be a parse error");
}

#[test]
fn wrap_without_command_is_parse_error() {
    let r = Cli::try_parse_from(["sentinel", "wrap"]);
    assert!(r.is_err(), "sentinel wrap without a command to wrap must be a parse error");
}

#[test]
fn unrecognized_subcommand_is_parse_error() {
    let r = Cli::try_parse_from(["sentinel", "echo", "hello"]);
    assert!(r.is_err(), "unrecognized subcommand must be a parse error (use `sentinel wrap echo hello`)");
}

#[test]
fn learn_on_non_wrap_verb_is_parse_error() {
    let r = Cli::try_parse_from(["sentinel", "status", "--learn"]);
    assert!(r.is_err(), "--learn must only be accepted on wrap");
}

#[test]
fn baseline_flag_is_no_longer_accepted() {
    let r = Cli::try_parse_from(["sentinel", "wrap", "--baseline", "echo", "hi"]);
    assert!(r.is_err(), "--baseline must no longer be accepted by clap");
}

// ---- --learn end-to-end fail-clear behavior ----------------------------------

/// Binary-invocation check: `sentinel wrap --learn echo hi` with stdin redirected
/// from /dev/null (non-TTY) must exit 64 (EX_USAGE) with stderr mentioning
/// "interactive terminal".
#[test]
fn non_tty_learn_returns_exit_64() {
    use std::process::{Command, Stdio};

    let sentinel = env!("CARGO_BIN_EXE_sentinel");

    let output = Command::new(sentinel)
        .arg("wrap")
        .arg("--learn")
        .arg("echo")
        .arg("hi")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .env_remove("SENTINEL_HOOK_DYLIB")
        .output()
        .expect("spawn sentinel");

    assert_eq!(
        output.status.code(),
        Some(64),
        "expected exit 64 (EX_USAGE), got {:?}; stderr={}",
        output.status.code(),
        String::from_utf8_lossy(&output.stderr),
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("interactive terminal") || stderr.contains("developer machine"),
        "expected --learn non-TTY error in stderr; got: {stderr:?}",
    );
}

// ---- Status parser tests ---------------------------------------------------

#[test]
fn status_bare_no_sub() {
    let cli = Cli::try_parse_from(["sentinel", "status"]).expect("parse");
    match cli.cmd {
        Cmd::Status { sub: None, verbose: false, json: false } => {}
        other => panic!("expected Status{{None}}, got {other:?}"),
    }
}

#[test]
fn status_review_no_uuid_parses() {
    let cli = Cli::try_parse_from(["sentinel", "status", "review"]).expect("parse");
    match cli.cmd {
        Cmd::Status { sub: Some(StatusSub::Review { run_uuid: None }), .. } => {}
        other => panic!("expected Status{{Review,None}}, got {other:?}"),
    }
}

#[test]
fn status_review_with_uuid_parses() {
    let cli = Cli::try_parse_from(["sentinel", "status", "review", "abc-123"]).expect("parse");
    match cli.cmd {
        Cmd::Status { sub: Some(StatusSub::Review { run_uuid: Some(u) }), .. } => {
            assert_eq!(u, "abc-123");
        }
        other => panic!("expected Status{{Review,abc-123}}, got {other:?}"),
    }
}

#[test]
fn status_review_rejects_json_flag() {
    let r = Cli::try_parse_from(["sentinel", "status", "review", "--json"]);
    assert!(r.is_err(), "--json on review must be rejected; got {:?}", r);
}

#[test]
fn status_logs_follow_parses() {
    let cli = Cli::try_parse_from(["sentinel", "status", "logs", "--follow"]).expect("parse");
    match cli.cmd {
        Cmd::Status { sub: Some(StatusSub::Logs { follow: true, json: false }), .. } => {}
        other => panic!("expected Status{{Logs,follow}}, got {other:?}"),
    }
}

// ---- Existing non-parser tests preserved verbatim from v0.1 ---------------

#[test]
fn audit_token_for_self_pid_succeeds() {
    let pid = unsafe { libc::getpid() };
    let token = sentinel_cli::audit_token::audit_token_for_pid(pid).expect("audit_token_for_pid");
    assert_eq!(token.val[5] as libc::pid_t, pid, "token.val[5] should equal pid");
}

#[test]
fn locate_dylib_with_env_override() {
    let tmp = tempfile::NamedTempFile::new().unwrap();
    unsafe { std::env::set_var("SENTINEL_HOOK_DYLIB", tmp.path()); }
    let p = sentinel_cli::locate::find_dylib().expect("find_dylib");
    assert_eq!(p, tmp.path().canonicalize().unwrap());
    unsafe { std::env::remove_var("SENTINEL_HOOK_DYLIB"); }
}
