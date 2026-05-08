//! sentinel — wrap a command under default-deny outbound network enforcement.

use clap::Parser;
use sentinel_cli::cli::{Cli, Cmd};
use sentinel_cli::{approve, install, ipc_client, run_orchestrator, shell_setup, trust_policy, uninstall, CliError};
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
        Cmd::External(argv) => {
            if argv.is_empty() {
                // Defensive — clap won't reach this with an empty external,
                // but Vec<OsString> is structurally non-empty by clap's contract.
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
        Cmd::TrustPolicy { path } => {
            // Probe the daemon first so the user gets a clean DaemonUnreachable
            // error instead of a hang on the tagged frame's connect.
            ipc_client::probe_daemon_alive(&sock)?;
            trust_policy::run_trust_policy(&sock, &path)?;
            Ok(0)
        }
        Cmd::Install { no_shell_integration, reinstall } => {
            install::run_install(&sock, &state, no_shell_integration, reinstall)
        }
        Cmd::Uninstall { force } => {
            uninstall::run_uninstall(&sock, &state, force)
        }
        Cmd::ShellSetup => {
            shell_setup::run_shell_setup()
        }
        Cmd::Status { verbose, json } => {
            sentinel_cli::status::run_status(&sock, &state, verbose, json)
        }
        Cmd::Logs { follow } => sentinel_cli::logs::run_logs(follow),
        Cmd::Approve { pattern, suffix, project, from_log, yes } => {
            approve::run_approve(&sock, approve::ApproveArgs {
                pattern, suffix, project, from_log, yes,
            })
        }
    }
}
