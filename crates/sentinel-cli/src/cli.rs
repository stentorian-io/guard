//! clap derive structs for the `sentinel` CLI.

use clap::{Parser, Subcommand};
use std::ffi::OsString;

#[derive(Parser, Debug)]
#[command(
    name = "sentinel",
    version,
    about = "Default-deny outbound network enforcement for wrapped commands",
    long_about = "\
Sentinel sandboxes outbound network egress from a command and its children.

USAGE:
  sentinel wrap <cmd> [args...]              Wrap a command under enforcement
  sentinel wrap --learn <cmd> [args...]      Record unknown destinations as user rules
                                             (TTY required; fails clear in non-TTY)

  sentinel status [logs|rules|denials|review|persistence] [--follow|--all|--json]
                                             Inspect daemon health, rules, denials
"
)]
pub struct Cli {
    #[command(subcommand)]
    pub cmd: Cmd,
}

#[derive(Subcommand, Debug)]
pub enum Cmd {
    /// Wrap a command under default-deny network enforcement.
    Wrap {
        /// Auto-allow unknown destinations and record them as user rules.
        /// TTY required; refuses to run in non-interactive environments.
        #[arg(long)]
        learn: bool,

        /// The command and its arguments to wrap.
        #[arg(trailing_var_arg = true, num_args = 1.., required = true)]
        argv: Vec<OsString>,
    },

    /// Inspect daemon health, rules, denials.
    Status {
        #[command(subcommand)]
        sub: Option<StatusSub>,
        /// Bare-status flag: verbose render. Only valid when `sub` is None.
        #[arg(long)]
        verbose: bool,
        /// Bare-status flag: JSON output. Only valid when `sub` is None.
        #[arg(long)]
        json: bool,
    },
}

/// Status read sub-verbs.
#[derive(Subcommand, Debug)]
pub enum StatusSub {
    /// Stream the JSONL forensic log.
    Logs {
        #[arg(long)] follow: bool,
        #[arg(long)] json: bool,
    },
    /// List active rules.
    Rules {
        /// Include built-in registry-allowlist rules.
        #[arg(long)] all: bool,
        #[arg(long)] json: bool,
    },
    /// View denials from a specific run_uuid.
    Denials {
        run_uuid: String,
        #[arg(long)] json: bool,
    },
    /// Interactively walk a previous run's denials. TTY-required.
    Review {
        run_uuid: Option<String>,
    },
    /// List detected persistence-write events.
    Persistence {
        /// Filter to a specific run_uuid.
        run_uuid: Option<String>,
        #[arg(long)] json: bool,
    },
}
