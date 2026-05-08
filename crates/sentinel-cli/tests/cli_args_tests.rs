use sentinel_cli::cli::{Cli, Cmd};
use clap::Parser;
use std::ffi::OsString;

// ---- CLI-08: root-default-wrap parser shape (D-03) ------------------------

#[test]
fn wrap_with_simple_command() {
    let cli = Cli::try_parse_from(["sentinel", "echo", "hello"]).expect("parse");
    assert!(!cli.learn);
    match cli.cmd {
        Cmd::External(argv) => {
            assert_eq!(argv, vec![OsString::from("echo"), OsString::from("hello")]);
        }
        other => panic!("expected External variant, got {other:?}"),
    }
}

#[test]
fn wrap_preserves_hyphen_args_in_wrapped_command() {
    // CLI-08 invariant (Assumption A1): hyphen-prefixed args after the
    // wrapped binary name are captured verbatim into the External vec —
    // they are NOT interpreted as Sentinel flags.
    let cli = Cli::try_parse_from(
        ["sentinel", "node", "-e", "console.log(1)"]
    ).expect("parse");
    assert!(!cli.learn);
    match cli.cmd {
        Cmd::External(argv) => {
            assert_eq!(argv, vec![
                OsString::from("node"),
                OsString::from("-e"),
                OsString::from("console.log(1)"),
            ]);
        }
        other => panic!("expected External variant, got {other:?}"),
    }
}

#[test]
fn external_subcommand_with_help_flag_routes_to_child() {
    // Assumption A2 verification: `sentinel echo --help` routes --help
    // into the wrapped argv, NOT to clap's help printer. clap's
    // top-level --help intercept happens BEFORE external_subcommand
    // engages; once we're in external mode, all trailing tokens are
    // captured opaquely.
    let cli = Cli::try_parse_from(["sentinel", "echo", "--help"]).expect("parse");
    match cli.cmd {
        Cmd::External(argv) => {
            assert_eq!(argv, vec![
                OsString::from("echo"),
                OsString::from("--help"),
            ]);
        }
        other => panic!("expected External variant, got {other:?}"),
    }
}

// ---- CLI-10: --learn top-level flag (D-04) -------------------------------

#[test]
fn learn_flag_top_level_before_wrapped_command() {
    // CLI-10: --learn BEFORE the wrapped command sets cli.learn.
    let cli = Cli::try_parse_from(["sentinel", "--learn", "npm", "install"]).expect("parse");
    assert!(cli.learn);
    match cli.cmd {
        Cmd::External(argv) => {
            assert_eq!(argv, vec![OsString::from("npm"), OsString::from("install")]);
        }
        other => panic!("expected External variant, got {other:?}"),
    }
}

#[test]
fn learn_after_wrapped_command_is_a_child_arg() {
    // Pitfall 1 / D-04 invariant: --learn AFTER the wrapped command
    // is captured as a child arg, NOT a Sentinel flag.
    let cli = Cli::try_parse_from(["sentinel", "npm", "install", "--learn"]).expect("parse");
    assert!(!cli.learn, "--learn after the wrapped command must NOT set cli.learn");
    match cli.cmd {
        Cmd::External(argv) => {
            assert_eq!(argv.last().unwrap(), &OsString::from("--learn"));
            assert_eq!(argv.len(), 3);
        }
        other => panic!("expected External variant, got {other:?}"),
    }
}

// ---- D-05: verb-vs-binary collision policy ---------------------------------

#[test]
fn named_verb_wins_over_external() {
    // D-05: `sentinel install` dispatches to the Install verb, even though
    // a binary named `install` could exist on $PATH.
    let cli = Cli::try_parse_from(["sentinel", "install"]).expect("parse");
    assert!(matches!(cli.cmd, Cmd::Install { .. }));
}

#[test]
fn full_path_bypasses_verb_match() {
    // D-05 escape: pass a full path to wrap a binary whose name collides
    // with a Sentinel verb.
    let cli = Cli::try_parse_from(["sentinel", "/usr/local/bin/status"]).expect("parse");
    match cli.cmd {
        Cmd::External(argv) => {
            assert_eq!(argv, vec![OsString::from("/usr/local/bin/status")]);
        }
        other => panic!("expected External variant, got {other:?}"),
    }
}

// ---- Negative tests --------------------------------------------------------

#[test]
fn bare_sentinel_no_args_is_parse_error() {
    let r = Cli::try_parse_from(["sentinel"]);
    assert!(r.is_err(), "bare sentinel with no command must be a parse error");
}

#[test]
fn baseline_flag_is_no_longer_accepted() {
    // D-04: --baseline was renamed to --learn. The old flag must produce
    // a clap error (unrecognized argument).
    let r = Cli::try_parse_from(["sentinel", "--baseline", "echo", "hi"]);
    assert!(r.is_err(), "--baseline must no longer be accepted by clap");
}

// ---- CLI-10 end-to-end fail-clear behavior --------------------------------

/// Binary-invocation check: `sentinel --learn echo hi` with stdin redirected
/// from /dev/null (non-TTY) must exit 64 (EX_USAGE) with stderr mentioning
/// "interactive terminal". This exercises the dispatch-arm gate added by
/// Plan 01 main.rs::real_main().
///
/// Pattern: the test follows the same approach as
/// `crates/sentinel-e2e/tests/non_tty_deny_with_log.rs` — build the binary,
/// run it, and inspect output.
#[test]
fn non_tty_learn_returns_exit_64() {
    use std::process::{Command, Stdio};

    // CARGO_BIN_EXE_<bin> is set by cargo at *compile time* for integration
    // tests in the same package as the binary, so it must be read with the
    // env! macro (not std::env::var, which queries runtime environment).
    let sentinel = env!("CARGO_BIN_EXE_sentinel");

    let output = Command::new(sentinel)
        .arg("--learn")
        .arg("echo")
        .arg("hi")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .env_remove("SENTINEL_HOOK_DYLIB")  // avoid loading the dylib
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
