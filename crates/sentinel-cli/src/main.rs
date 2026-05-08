//! sentinel — wrap a command under default-deny outbound network enforcement.

use clap::Parser;
use sentinel_cli::cli::{Cli, Cmd};
use sentinel_cli::{run_orchestrator, CliError};
use sentinel_daemon::state_dir::{default_state_dir, socket_path};
use std::path::PathBuf;

fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn")),
        )
        .init();
    match real_main() {
        Ok(code) => std::process::exit(code),
        Err(e) => {
            eprintln!("sentinel: {e}");
            std::process::exit(70); // EX_SOFTWARE
        }
    }
}

fn real_main() -> Result<i32, CliError> {
    let cli = Cli::parse();
    let state = std::env::var_os("SENTINEL_STATE_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(default_state_dir);
    let sock = socket_path(&state);

    // CLI-10 / CR-01: --learn is only meaningful on the wrap path (Cmd::External).
    // Reject it on any named verb (Setup / Status). Verb collisions with old v0.1
    // names (install, uninstall, status, logs, approve, trust-policy, shell-setup)
    // route to Cmd::External per D-11 silent fall-through; --learn there would
    // try to learn while spawning /usr/bin/install or similar, which is wrong.
    if cli.learn && !matches!(cli.cmd, Cmd::External(_)) {
        eprintln!(
            "sentinel: --learn is only valid when wrapping a command \
             (e.g., `sentinel --learn npm install`); it cannot be combined \
             with named verbs"
        );
        return Ok(64); // EX_USAGE
    }

    match cli.cmd {
        Cmd::External(argv) => {
            if argv.is_empty() {
                eprintln!("sentinel: missing command to wrap");
                return Ok(64); // EX_USAGE
            }
            if cli.learn && !sentinel_cli::tty::stdin_is_tty() {
                eprintln!(
                    "sentinel: --learn requires an interactive terminal \
                     (run on a developer machine, not in CI)"
                );
                return Ok(64); // EX_USAGE
            }
            run_orchestrator::run(&sock, &state, argv, cli.learn)
        }
        Cmd::Setup { target, remove, reinstall, yes } => {
            sentinel_cli::setup::run_setup(&sock, &state, target, remove, reinstall, yes)
        }
        Cmd::Status { sub, verbose, json } => match sub {
            None => sentinel_cli::status::run_status(&sock, &state, verbose, json),
            Some(sentinel_cli::cli::StatusSub::Logs { follow, json }) => {
                sentinel_cli::logs::run_logs(follow, json)
            }
            Some(sentinel_cli::cli::StatusSub::Rules { all, project, json }) => {
                sentinel_cli::status::rules::run(&sock, all, project, json)
            }
            Some(sentinel_cli::cli::StatusSub::Trust { json }) => {
                sentinel_cli::status::trust::run(&sock, json)
            }
            Some(sentinel_cli::cli::StatusSub::Denials { run_uuid, json }) => {
                sentinel_cli::status::denials::run(&run_uuid, json)
            }
            Some(sentinel_cli::cli::StatusSub::Review { run_uuid }) => {
                sentinel_cli::status::review::run(&sock, run_uuid)
            }
        },
    }
}
