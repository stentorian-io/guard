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

    match cli.cmd {
        Cmd::Wrap { learn, argv } => {
            if learn && !sentinel_cli::tty::stdin_is_tty() {
                eprintln!(
                    "sentinel: --learn requires an interactive terminal \
                     (run on a developer machine, not in CI)"
                );
                return Ok(64); // EX_USAGE
            }
            run_orchestrator::run(&sock, &state, argv, learn)
        }
        Cmd::Status { sub, verbose, json } => {
            if sub.is_some() && (verbose || json) {
                eprintln!(
                    "sentinel: --verbose / --json must follow the sub-verb \
                     (e.g., `status rules --json`, not `status --json rules`)"
                );
                return Ok(64); // EX_USAGE
            }
            match sub {
                None => sentinel_cli::status::run_status(&sock, &state, verbose, json),
                Some(sentinel_cli::cli::StatusSub::Logs { follow, json }) => {
                    sentinel_cli::logs::run_logs(follow, json)
                }
                Some(sentinel_cli::cli::StatusSub::Rules { all, json }) => {
                    sentinel_cli::status::rules::run(&sock, all, json)
                }
                Some(sentinel_cli::cli::StatusSub::Denials { run_uuid, json }) => {
                    sentinel_cli::status::denials::run(&run_uuid, json)
                }
                Some(sentinel_cli::cli::StatusSub::Review { run_uuid }) => {
                    sentinel_cli::status::review::run(&sock, run_uuid)
                }
                Some(sentinel_cli::cli::StatusSub::Persistence { run_uuid, json }) => {
                    sentinel_cli::status::persistence::run(run_uuid.as_deref(), json)
                }
            }
        },
    }
}
