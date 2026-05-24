use clap::Parser;
use guard_cli::cli::{Cli, Cmd, StatusSub};
use std::ffi::OsString;

// ---- stt-guard init parser shape ------------------------------------------------

#[test]
fn init_bare_parses() {
    let cli = Cli::try_parse_from(["stt-guard", "init"]).expect("parse");
    match cli.cmd {
        Cmd::Init { yes } => {
            assert!(!yes);
        }
        other => panic!("expected Init variant, got {other:?}"),
    }
}

#[test]
fn init_yes_flag_parses() {
    let cli = Cli::try_parse_from(["stt-guard", "init", "--yes"]).expect("parse");
    match cli.cmd {
        Cmd::Init { yes } => {
            assert!(yes);
        }
        other => panic!("expected Init variant, got {other:?}"),
    }
}

#[test]
fn init_short_y_flag_parses() {
    let cli = Cli::try_parse_from(["stt-guard", "init", "-y"]).expect("parse");
    match cli.cmd {
        Cmd::Init { yes } => {
            assert!(yes);
        }
        other => panic!("expected Init variant, got {other:?}"),
    }
}

// ---- stt-guard wrap parser shape -----------------------------------------------

#[test]
fn wrap_with_simple_command() {
    let cli = Cli::try_parse_from(["stt-guard", "wrap", "echo", "hello"]).expect("parse");
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
    let cli =
        Cli::try_parse_from(["stt-guard", "wrap", "node", "-e", "console.log(1)"]).expect("parse");
    match cli.cmd {
        Cmd::Wrap { learn, argv } => {
            assert!(!learn);
            assert_eq!(
                argv,
                vec![
                    OsString::from("node"),
                    OsString::from("-e"),
                    OsString::from("console.log(1)"),
                ]
            );
        }
        other => panic!("expected Wrap variant, got {other:?}"),
    }
}

#[test]
fn wrap_with_help_flag_routes_to_child() {
    let cli = Cli::try_parse_from(["stt-guard", "wrap", "echo", "--help"]).expect("parse");
    match cli.cmd {
        Cmd::Wrap { argv, .. } => {
            assert_eq!(
                argv,
                vec![OsString::from("echo"), OsString::from("--help"),]
            );
        }
        other => panic!("expected Wrap variant, got {other:?}"),
    }
}

// ---- --learn flag on wrap ----------------------------------------------------

#[test]
fn learn_flag_on_wrap_subcommand() {
    let cli =
        Cli::try_parse_from(["stt-guard", "wrap", "--learn", "npm", "install"]).expect("parse");
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
    let cli =
        Cli::try_parse_from(["stt-guard", "wrap", "npm", "install", "--learn"]).expect("parse");
    match cli.cmd {
        Cmd::Wrap { learn, argv } => {
            assert!(
                !learn,
                "--learn after the wrapped command must NOT set learn flag"
            );
            assert_eq!(argv.last().unwrap(), &OsString::from("--learn"));
            assert_eq!(argv.len(), 3);
        }
        other => panic!("expected Wrap variant, got {other:?}"),
    }
}

// ---- Negative tests --------------------------------------------------------

#[test]
fn bare_guard_no_args_is_parse_error() {
    let r = Cli::try_parse_from(["stt-guard"]);
    assert!(
        r.is_err(),
        "bare stt-guard with no subcommand must be a parse error"
    );
}

#[test]
fn wrap_without_command_is_parse_error() {
    let r = Cli::try_parse_from(["stt-guard", "wrap"]);
    assert!(
        r.is_err(),
        "stt-guard wrap without a command to wrap must be a parse error"
    );
}

#[test]
fn unrecognized_subcommand_is_parse_error() {
    let r = Cli::try_parse_from(["stt-guard", "echo", "hello"]);
    assert!(
        r.is_err(),
        "unrecognized subcommand must be a parse error (use `stt-guard wrap echo hello`)"
    );
}

#[test]
fn learn_on_non_wrap_verb_is_parse_error() {
    let r = Cli::try_parse_from(["stt-guard", "status", "--learn"]);
    assert!(r.is_err(), "--learn must only be accepted on wrap");
}

#[test]
fn baseline_flag_is_no_longer_accepted() {
    let r = Cli::try_parse_from(["stt-guard", "wrap", "--baseline", "echo", "hi"]);
    assert!(r.is_err(), "--baseline must no longer be accepted by clap");
}

// ---- Hook dylib discovery ---------------------------------------------------

#[test]
fn hook_dylib_env_override_takes_precedence() {
    struct RestoreEnv {
        key: &'static str,
        previous: Option<std::ffi::OsString>,
    }

    impl Drop for RestoreEnv {
        fn drop(&mut self) {
            unsafe {
                match &self.previous {
                    Some(value) => std::env::set_var(self.key, value),
                    None => std::env::remove_var(self.key),
                }
            }
        }
    }

    let tmp = tempfile::tempdir().expect("tempdir");
    let dylib = tmp.path().join("custom-stt-guard-hook.dylib");
    std::fs::write(&dylib, []).expect("write placeholder dylib");

    let _restore_hook = RestoreEnv {
        key: "STT_GUARD_HOOK_DYLIB",
        previous: std::env::var_os("STT_GUARD_HOOK_DYLIB"),
    };
    let _restore_state = RestoreEnv {
        key: "STT_GUARD_STATE_DIR",
        previous: std::env::var_os("STT_GUARD_STATE_DIR"),
    };
    unsafe {
        std::env::set_var("STT_GUARD_HOOK_DYLIB", &dylib);
        std::env::set_var("STT_GUARD_STATE_DIR", tmp.path());
    }

    let found = guard_cli::locate::find_dylib().expect("find dylib");

    assert_eq!(found, dylib.canonicalize().expect("canonicalize dylib"));
}

// ---- --learn end-to-end fail-clear behavior ----------------------------------

/// Binary-invocation check: `stt-guard wrap --learn echo hi` with stdin redirected
/// from /dev/null (non-TTY) must exit 64 (EX_USAGE) with stderr mentioning
/// "interactive terminal".
#[test]
fn non_tty_learn_returns_exit_64() {
    use std::process::{Command, Stdio};

    let stt_guard = env!("CARGO_BIN_EXE_stt-guard");

    let output = Command::new(stt_guard)
        .arg("wrap")
        .arg("--learn")
        .arg("echo")
        .arg("hi")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .env_remove("STT_GUARD_HOOK_DYLIB")
        .output()
        .expect("spawn stt-guard");

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
    let cli = Cli::try_parse_from(["stt-guard", "status"]).expect("parse");
    match cli.cmd {
        Cmd::Status { sub: None } => {}
        other => panic!("expected Status{{None}}, got {other:?}"),
    }
}

#[test]
fn status_review_no_uuid_parses() {
    let cli = Cli::try_parse_from(["stt-guard", "status", "review"]).expect("parse");
    match cli.cmd {
        Cmd::Status {
            sub: Some(StatusSub::Review { run_uuid: None }),
            ..
        } => {}
        other => panic!("expected Status{{Review,None}}, got {other:?}"),
    }
}

#[test]
fn status_review_with_uuid_parses() {
    let cli = Cli::try_parse_from(["stt-guard", "status", "review", "abc-123"]).expect("parse");
    match cli.cmd {
        Cmd::Status {
            sub: Some(StatusSub::Review { run_uuid: Some(u) }),
            ..
        } => {
            assert_eq!(u, "abc-123");
        }
        other => panic!("expected Status{{Review,abc-123}}, got {other:?}"),
    }
}

#[test]
fn status_logs_bare_parses() {
    let cli = Cli::try_parse_from(["stt-guard", "status", "logs"]).expect("parse");
    match cli.cmd {
        Cmd::Status {
            sub: Some(StatusSub::Logs),
            ..
        } => {}
        other => panic!("expected Status{{Logs}}, got {other:?}"),
    }
}

#[test]
fn status_rules_include_built_in_parses() {
    let cli =
        Cli::try_parse_from(["stt-guard", "status", "rules", "--include-built-in"]).expect("parse");
    match cli.cmd {
        Cmd::Status {
            sub:
                Some(StatusSub::Rules {
                    include_built_in: true,
                    ..
                }),
            ..
        } => {}
        other => panic!("expected Status{{Rules,include_built_in}}, got {other:?}"),
    }
}

#[test]
fn status_rejects_removed_flags() {
    for args in [
        vec!["stt-guard", "status", "--verbose"],
        vec!["stt-guard", "status", "--json"],
        vec!["stt-guard", "status", "logs", "--follow"],
        vec!["stt-guard", "status", "logs", "--json"],
        vec!["stt-guard", "status", "rules", "--json"],
        vec!["stt-guard", "status", "rules", "--all"],
        vec!["stt-guard", "status", "denials", "abc", "--json"],
    ] {
        let r = Cli::try_parse_from(&args);
        assert!(r.is_err(), "removed flag must be rejected: {:?}", args);
    }
}

// ---- Existing non-parser tests preserved verbatim from v0.1 ---------------

#[test]
fn audit_token_for_self_pid_succeeds() {
    let pid = unsafe { libc::getpid() };
    let token = guard_cli::audit_token::audit_token_for_pid(pid).expect("audit_token_for_pid");
    assert_eq!(
        token.val[5] as libc::pid_t, pid,
        "token.val[5] should equal pid"
    );
}
