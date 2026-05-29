//! stt-guard — wrap a command under default-deny outbound network enforcement.

use clap::Parser;
use guard_cli::cli::{Cli, Cmd};
use guard_cli::{CliError, run_orchestrator};
use guard_daemon::state_dir::{default_state_dir, socket_path};

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
            eprintln!("stt-guard: {e}");
            std::process::exit(70); // EX_SOFTWARE
        }
    }
}

fn real_main() -> Result<i32, CliError> {
    let cli = Cli::parse();

    match cli.cmd {
        Cmd::InstallSystem { yes } => {
            guard_cli::install::system::print_plan();
            if !yes {
                eprintln!();
                if !guard_cli::tty::confirm("Proceed?")? {
                    eprintln!("Aborted.");
                    return Ok(0);
                }
            }
            eprintln!();
            guard_cli::install::system::run_install()?;
            Ok(0)
        }
        Cmd::Update { check, version } => guard_cli::install::update::run_update(check, version),
        Cmd::Wrap { learn, argv } => {
            if learn && !guard_cli::tty::stdin_is_tty() {
                eprintln!(
                    "stt-guard: --learn requires an interactive terminal \
                     (run on a developer machine, not in CI)"
                );
                return Ok(64); // EX_USAGE
            }
            let state = resolve_state_dir();
            let sock = socket_path(&state);
            guard_cli::ensure_daemon::ensure_daemon(&sock, &state)?;
            run_orchestrator::run(&sock, &state, &argv, learn)
        }
        Cmd::Status { sub } => {
            let state = resolve_state_dir();
            let sock = socket_path(&state);
            match sub {
                // Local-only commands: install gate but no daemon needed.
                Some(guard_cli::cli::StatusSub::Logs) => {
                    guard_cli::ensure_daemon::require_installed()?;
                    guard_cli::logs::run_logs()
                }
                Some(guard_cli::cli::StatusSub::Denials { run_uuid }) => {
                    guard_cli::ensure_daemon::require_installed()?;
                    guard_cli::status::denials::run(&run_uuid)
                }
                Some(guard_cli::cli::StatusSub::Persistence { run_uuid }) => {
                    guard_cli::ensure_daemon::require_installed()?;
                    guard_cli::status::persistence::run(run_uuid.as_deref())
                }
                Some(guard_cli::cli::StatusSub::Advisory { advisory_id }) => {
                    guard_cli::ensure_daemon::require_installed()?;
                    guard_cli::status::advisory::run(&advisory_id)
                }
                // IPC-dependent commands: ensure daemon first.
                None => {
                    guard_cli::ensure_daemon::ensure_daemon(&sock, &state)?;
                    guard_cli::status::run_status(&sock, &state)
                }
                Some(guard_cli::cli::StatusSub::Rules {
                    include_built_in,
                    disable,
                    enable,
                    reason,
                }) => {
                    guard_cli::ensure_daemon::ensure_daemon(&sock, &state)?;
                    guard_cli::status::rules::run(&sock, include_built_in, disable, enable, reason)
                }
                Some(guard_cli::cli::StatusSub::Review { run_uuid }) => {
                    guard_cli::ensure_daemon::ensure_daemon(&sock, &state)?;
                    guard_cli::status::review::run(&sock, run_uuid)
                }
            }
        }
    }
}

/// Resolve the state directory. In hardened mode (which is the only mode),
/// if the system state dir exists, use it; otherwise fall back to the
/// user-level default (for development/testing via `STT_GUARD_STATE_DIR`).
fn resolve_state_dir() -> std::path::PathBuf {
    let system = guard_cli::install::system::system_state_dir();
    if system.exists() {
        return system;
    }
    default_state_dir()
}
