use sentinel_cli::cli::{Cli, Cmd};
use clap::Parser;
use std::ffi::OsString;

#[test]
fn run_with_simple_command() {
    let cli = Cli::try_parse_from(["sentinel", "run", "echo", "hello"]).expect("parse");
    match cli.cmd {
        Cmd::Run { command, .. } => {
            assert_eq!(command, vec![OsString::from("echo"), OsString::from("hello")]);
        }
        other => panic!("expected Run variant, got {other:?}"),
    }
}

#[test]
fn run_with_dash_dash_separator_and_hyphen_args() {
    let cli = Cli::try_parse_from(["sentinel", "run", "--", "node", "-e", "console.log(1)"]).expect("parse");
    match cli.cmd {
        Cmd::Run { command, .. } => {
            assert_eq!(command, vec![
                OsString::from("node"),
                OsString::from("-e"),
                OsString::from("console.log(1)"),
            ]);
        }
        other => panic!("expected Run variant, got {other:?}"),
    }
}

#[test]
fn run_no_command_is_parse_error() {
    let r = Cli::try_parse_from(["sentinel", "run"]);
    assert!(r.is_err(), "missing command must be a parse error");
}

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
