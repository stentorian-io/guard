//! Tests for the `sentinel trust-policy <path>` clap parsing surface and the
//! non-TTY fail-closed behavior (T-02-06b-02).

use clap::Parser;
use sentinel_cli::cli::{Cli, Cmd};
use std::path::PathBuf;

#[test]
fn trust_policy_parses_path_arg() {
    let cli = Cli::try_parse_from(["sentinel", "trust-policy", "/tmp/.sentinel.toml"])
        .expect("parse");
    match cli.cmd {
        Cmd::TrustPolicy { path } => {
            assert_eq!(path, PathBuf::from("/tmp/.sentinel.toml"));
        }
        other => panic!("expected TrustPolicy variant, got {other:?}"),
    }
}

#[test]
fn trust_policy_requires_path_arg() {
    let r = Cli::try_parse_from(["sentinel", "trust-policy"]);
    assert!(r.is_err(), "missing path must be a parse error");
}

#[test]
fn run_subcommand_still_parses() {
    // Sanity: adding TrustPolicy does not break the existing Run variant.
    let cli = Cli::try_parse_from(["sentinel", "run", "echo", "hello"]).expect("parse");
    matches!(cli.cmd, Cmd::Run { .. });
}

/// Non-TTY (CI/scripts) calling `run_trust_policy` MUST fail with a diagnostic
/// rather than auto-trusting. T-02-06b-02 mitigation.
///
/// `cargo test` runs with stdin redirected from /dev/null (not a TTY), so this
/// test naturally exercises the non-TTY path. The function reads + displays
/// the file BEFORE the TTY check, so we need a real .sentinel.toml on disk to
/// reach the prompt.
#[test]
fn run_trust_policy_in_non_tty_returns_error() {
    let tmp = tempfile::tempdir().unwrap();
    let toml_path = tmp.path().join(".sentinel.toml");
    let body = "version = 1\n\n[[rules]]\nkind = \"allow\"\nmatch = \"exact\"\npattern = \"npmjs.com\"\nreason = \"npm registry\"\n";
    std::fs::write(&toml_path, body).unwrap();

    // Bogus socket path — but the function should fail at the TTY check BEFORE
    // attempting the socket. (Display + parse + canonicalize all succeed first.)
    let bogus_sock = tmp.path().join("does-not-exist.sock");
    let r = sentinel_cli::trust_policy::run_trust_policy(&bogus_sock, &toml_path);
    assert!(r.is_err(), "non-TTY trust-policy must fail");
    let err_msg = format!("{}", r.unwrap_err());
    assert!(
        err_msg.contains("terminal") || err_msg.contains("TTY") || err_msg.contains("tty"),
        "error must mention terminal/TTY: got {err_msg:?}"
    );
}
