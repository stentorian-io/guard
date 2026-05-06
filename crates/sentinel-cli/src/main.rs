//! sentinel — wrap a command under default-deny outbound network enforcement.

use clap::Parser;
use sentinel_cli::cli::{Cli, Cmd};
use sentinel_cli::{audit_token, install, ipc_client, locate, shell_setup, spawn, trust_policy, uninstall, CliError};
use sentinel_daemon::state_dir::{default_state_dir, socket_path};
use std::ffi::OsStr;
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
        Cmd::Run { command } => {
            if command.is_empty() {
                eprintln!("sentinel run: missing command");
                return Ok(64); // EX_USAGE
            }
            let program = PathBuf::from(&command[0]);
            let args: Vec<&OsStr> = command[1..].iter().map(|s| s.as_os_str()).collect();
            let dylib =
                locate::find_dylib().map_err(|e| CliError::DylibNotFound(e.to_string()))?;

            // ISS-08 remediation — DAEMON-FIRST SEQUENCING:
            // Probe the daemon BEFORE asking it to do anything. T-01-08-06
            // promises the CLI exits 70 BEFORE having spawned the child if
            // the daemon is unreachable.
            ipc_client::probe_daemon_alive(&sock)?;

            // Phase 2 D-29: PrepareSnapshot — ask the daemon to walk cwd for
            // .sentinel.toml, merge curated + project + user rules, and write
            // a per-run snapshot. The returned manifest path is what the
            // dylib will read at ctor time via SENTINEL_SNAPSHOT_MANIFEST.
            //
            // This replaces Phase 1's daemon-startup snapshot: each `sentinel
            // run` invocation now gets a fresh per-run snapshot tailored to
            // its working directory.
            let cwd =
                std::env::current_dir().map_err(|e| CliError::Other(format!("getcwd: {e}")))?;
            let (manifest_path, _run_uuid) = ipc_client::prepare_snapshot(&sock, &cwd)?;

            // Daemon is alive and per-run snapshot is published — spawn the
            // wrapped child with both SENTINEL_SNAPSHOT_MANIFEST (per-run) and
            // SENTINEL_DAEMON_SOCKET (so the dylib's IPC client can talk back
            // for fork/exec/dylib_loaded events).
            let pid = spawn::spawn_wrapped(&program, &args, &dylib, &manifest_path, &sock)?;

            // Derive audit token, register with daemon (Phase 1 unchanged).
            let token = audit_token::audit_token_for_pid(pid)
                .map_err(|e| CliError::DaemonUnreachable(format!("audit_token: {e}")))?;
            ipc_client::register_root_with_daemon(&sock, token)?;

            // Wait for child exit.
            let mut status: libc::c_int = 0;
            let waited = unsafe { libc::waitpid(pid, &mut status, 0) };
            if waited < 0 {
                return Err(CliError::Io(std::io::Error::last_os_error()));
            }
            let exit_code = if libc::WIFEXITED(status) {
                libc::WEXITSTATUS(status)
            } else {
                128 + libc::WTERMSIG(status)
            };
            Ok(exit_code)
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
        Cmd::Approve { .. } => {
            eprintln!("sentinel approve: pending plan 03-11");
            Ok(0)
        }
    }
}
