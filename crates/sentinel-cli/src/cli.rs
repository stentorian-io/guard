//! clap derive structs for the `sentinel` CLI.

use clap::{Parser, Subcommand};
use std::ffi::OsString;
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(name = "sentinel", version, about = "Default-deny outbound network enforcement for wrapped commands")]
pub struct Cli {
    #[command(subcommand)]
    pub cmd: Cmd,
}

#[derive(Subcommand, Debug)]
pub enum Cmd {
    /// Wrap and execute a command under default-deny network enforcement.
    ///
    /// Use `--` to separate sentinel options from the wrapped command:
    ///   sentinel run -- node -e 'require("net").connect(443, "host")'
    Run {
        /// The wrapped command and its arguments.
        #[arg(trailing_var_arg = true, allow_hyphen_values = true, num_args = 1.., required = true)]
        command: Vec<OsString>,
        /// Record allow-and-log to per-project .sentinel.toml; show diff+confirm on exit (POL-04).
        #[arg(long)]
        baseline: bool,
    },

    /// Trust a project-local `.sentinel.toml` so its rules apply to subsequent
    /// `sentinel run` invocations from that working tree (D-38).
    ///
    /// Reads + displays the file, prompts for y/n at the terminal, computes
    /// SHA-256, and sends a `TrustPolicy` IPC to the daemon. The daemon
    /// re-hashes the file as defense-in-depth (T-02-06a-01).
    TrustPolicy {
        /// Path to the .sentinel.toml to trust (absolute or relative).
        #[arg(value_name = "PATH")]
        path: PathBuf,
    },

    /// Install the user-level daemon, LaunchAgent, and shell integration.
    Install {
        /// Skip dotfile mutation; install daemon + plist + state/log dirs only (D-68).
        #[arg(long)]
        no_shell_integration: bool,
        /// Force-clean reinstall: wipe install_artifacts and re-derive (D-63).
        #[arg(long)]
        reinstall: bool,
    },

    /// Reverse `sentinel install` — remove daemon, LaunchAgent, marker blocks, state, logs.
    Uninstall {
        /// Skip confirmation prompt.
        #[arg(long)]
        force: bool,
    },

    /// Add marker blocks to rc files without touching the daemon (post-install).
    ShellSetup,

    /// Show daemon health, tracked roots, recent gaps, and remediation hints.
    Status {
        #[arg(long)]
        verbose: bool,
        #[arg(long)]
        json: bool,
    },

    /// Stream the JSONL forensic log (--follow tails with rotation detection).
    Logs {
        #[arg(long)]
        follow: bool,
    },

    /// Add a user rule to the SQLite rule store (or .sentinel.toml with --project).
    Approve {
        /// Hostname (exact match by default, suffix match with --suffix).
        pattern: Option<String>,
        /// Treat the pattern as a suffix rather than an exact host.
        #[arg(long)]
        suffix: bool,
        /// Write to closest .sentinel.toml + auto-trust instead of SQLite.
        #[arg(long)]
        project: bool,
        /// Batch-approve all denied destinations from a previous run_uuid.
        #[arg(long, value_name = "RUN_UUID")]
        from_log: Option<String>,
        /// Skip confirmation prompt.
        #[arg(long, short)]
        yes: bool,
    },
}
