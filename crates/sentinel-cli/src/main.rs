//! sentinel — wrap a command under default-deny outbound network enforcement.

use clap::Parser;
use sentinel_cli::cli::{Cli, Cmd};
use sentinel_cli::{run_orchestrator, CliError};
use sentinel_daemon::state_dir::{default_state_dir, socket_path};

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
    let state = default_state_dir();
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
            sentinel_cli::ensure_daemon::ensure_daemon(&sock, &state)?;
            run_orchestrator::run(&sock, &state, argv, learn)
        }
        Cmd::Status { sub } => {
            match sub {
                // Local-only commands: no daemon needed.
                Some(sentinel_cli::cli::StatusSub::Logs) => {
                    sentinel_cli::logs::run_logs()
                }
                Some(sentinel_cli::cli::StatusSub::Denials { run_uuid }) => {
                    sentinel_cli::status::denials::run(&run_uuid)
                }
                Some(sentinel_cli::cli::StatusSub::Persistence { run_uuid }) => {
                    sentinel_cli::status::persistence::run(run_uuid.as_deref())
                }
                Some(sentinel_cli::cli::StatusSub::Advisory { advisory_id }) => {
                    sentinel_cli::status::advisory::run(&advisory_id)
                }
                // IPC-dependent commands: ensure daemon first.
                None => {
                    sentinel_cli::ensure_daemon::ensure_daemon(&sock, &state)?;
                    sentinel_cli::status::run_status(&sock, &state)
                }
                Some(sentinel_cli::cli::StatusSub::Rules { include_built_in }) => {
                    sentinel_cli::ensure_daemon::ensure_daemon(&sock, &state)?;
                    sentinel_cli::status::rules::run(&sock, include_built_in)
                }
                Some(sentinel_cli::cli::StatusSub::Review { run_uuid }) => {
                    sentinel_cli::ensure_daemon::ensure_daemon(&sock, &state)?;
                    sentinel_cli::status::review::run(&sock, run_uuid)
                }
            }
        },
    }
}
