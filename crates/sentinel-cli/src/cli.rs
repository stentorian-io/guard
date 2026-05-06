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
}
