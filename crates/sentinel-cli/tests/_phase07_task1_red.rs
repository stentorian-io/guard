//! Phase 07 Plan 04 Task 1 RED gate.
//!
//! Asserts the new `Cmd::Setup` / `Cmd::Status` shape and `SetupTarget` /
//! `StatusSub` enums compile + parse. This file fails to compile against the
//! current cli.rs (which still has v0.1 variants) — it goes GREEN once Task 1
//! lands the new shape. After the GREEN commit, this file is REMOVED in
//! Task 3 (the canonical replacement tests live in `cli_args_tests.rs`).

use clap::Parser;
use sentinel_cli::cli::{Cli, Cmd, SetupTarget, StatusSub};

#[test]
fn red_setup_bare_no_target_no_flags() {
    let cli = Cli::try_parse_from(["sentinel", "setup"]).expect("parse");
    match cli.cmd {
        Cmd::Setup { target, remove, reinstall, yes } => {
            assert!(target.is_none());
            assert!(!remove);
            assert!(!reinstall);
            assert!(!yes);
        }
        other => panic!("expected Setup, got {other:?}"),
    }
}

#[test]
fn red_setup_daemon_target() {
    let cli = Cli::try_parse_from(["sentinel", "setup", "daemon"]).expect("parse");
    match cli.cmd {
        Cmd::Setup { target: Some(SetupTarget::Daemon), .. } => {}
        other => panic!("expected Setup{{Daemon}}, got {other:?}"),
    }
}

#[test]
fn red_status_review_subcommand() {
    let cli = Cli::try_parse_from(["sentinel", "status", "review"]).expect("parse");
    match cli.cmd {
        Cmd::Status { sub: Some(StatusSub::Review { run_uuid: None }), .. } => {}
        other => panic!("expected Status{{Review,None}}, got {other:?}"),
    }
}
