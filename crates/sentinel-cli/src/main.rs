//! sentinel — wrap a command under default-deny outbound network enforcement.

use clap::Parser;
use sentinel_cli::cli::{Cli, Cmd};
use sentinel_cli::{audit_token, ipc_client, locate, spawn, CliError};
use sentinel_daemon::state_dir::{default_state_dir, manifest_path, socket_path};
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
            let state = std::env::var_os("SENTINEL_STATE_DIR")
                .map(PathBuf::from)
                .unwrap_or_else(default_state_dir);
            let mfst = manifest_path(&state);
            if !mfst.exists() {
                return Err(CliError::DaemonUnreachable(format!(
                    "manifest not found at {} — run `sentineld dev-install` first",
                    mfst.display()
                )));
            }
            let sock = socket_path(&state);

            // ISS-08 remediation — DAEMON-FIRST SEQUENCING:
            // Probe the daemon BEFORE spawning the wrapped child. T-01-08-06
            // promises "exits with code 70 BEFORE having spawned the child if
            // daemon unreachable" — that promise is only kept if the connect
            // attempt happens before posix_spawnp. The probe is connect-only:
            // success of `connect_timeout` against the daemon's bound socket
            // is sufficient liveness evidence (a non-running daemon yields
            // ECONNREFUSED or ENOENT). No frame is sent; the stream is closed
            // immediately. The daemon's accept-side handler (plan 05) treats
            // the resulting EOF on read_frame as a benign liveness probe.
            ipc_client::probe_daemon_alive(&sock)?;

            // Daemon is alive — spawn the wrapped child.
            let pid = spawn::spawn_wrapped(&program, &args, &dylib, &mfst)?;

            // Derive audit token, register with daemon.
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
    }
}
