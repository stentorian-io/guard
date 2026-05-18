//! clap derive structs for the `sentinel` CLI.

use clap::{Parser, Subcommand, ValueEnum};
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
  sentinel wrap --learn <cmd> [args...]      Record unknown destinations to .sentinel.toml
                                             (TTY required; fails clear in non-TTY)

  sentinel setup [daemon|shell] [--remove|--reinstall] [-y]
                                             Install / repair / remove components
  sentinel status [logs|rules|trust|denials|review|persistence] [--follow|--all|--project|--json]
                                             Inspect daemon health, rules, trust, denials
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
        /// Auto-allow unknown destinations and record them to .sentinel.toml.
        /// TTY required; refuses to run in non-interactive environments.
        #[arg(long)]
        learn: bool,

        /// The command and its arguments to wrap.
        #[arg(trailing_var_arg = true, num_args = 1.., required = true)]
        argv: Vec<OsString>,
    },

    /// Install / repair / remove daemon and shell components.
    Setup {
        /// Optional component target: `daemon` (LaunchAgent + plist + state)
        /// or `shell` (marker blocks). Bare `setup` targets all components.
        #[arg(value_enum)]
        target: Option<SetupTarget>,
        /// Remove the targeted component(s) instead of installing.
        #[arg(long, conflicts_with = "reinstall")]
        remove: bool,
        /// Force-clean reinstall: wipe + re-derive.
        #[arg(long, conflicts_with = "remove")]
        reinstall: bool,
        /// Skip TTY confirmation prompts. `--force` is NOT a synonym.
        #[arg(long, short = 'y')]
        yes: bool,
    },

    /// Inspect daemon health, rules, trust, denials.
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

    /// Verify and repair installation integrity.
    /// Re-derives HMAC key (if missing), hook hash, and re-bootstraps agents.
    Repair,

    /// Emergency escape hatch: bootout daemon + watchdog, clear tracked roots,
    /// so all wrapped processes lose enforcement immediately.
    UnwrapAll {
        /// Skip TTY confirmation prompt.
        #[arg(long, short = 'y')]
        yes: bool,
    },
}

/// Per-target setup dispatch (D-15).
#[derive(ValueEnum, Debug, Clone, Copy, PartialEq, Eq)]
pub enum SetupTarget {
    /// Daemon LaunchAgent + plist + state/log dirs only (no shell aliases).
    Daemon,
    /// Shell marker blocks only (no daemon touches).
    Shell,
}

/// Status read sub-verbs (CLI-15..CLI-19). `--json` available everywhere
/// EXCEPT `Review` per D-23 (review is interactive, not machine-readable).
#[derive(Subcommand, Debug)]
pub enum StatusSub {
    /// Stream the JSONL forensic log (CLI-15).
    Logs {
        #[arg(long)] follow: bool,
        #[arg(long)] json: bool,
    },
    /// List active rules (CLI-16).
    Rules {
        /// Include built-in registry-allowlist rules.
        #[arg(long)] all: bool,
        /// Filter to rules from the closest .sentinel.toml above cwd.
        #[arg(long)] project: bool,
        #[arg(long)] json: bool,
    },
    /// List trusted .sentinel.toml files (CLI-17).
    Trust {
        #[arg(long)] json: bool,
    },
    /// View denials from a specific run_uuid (CLI-18).
    Denials {
        run_uuid: String,
        #[arg(long)] json: bool,
    },
    /// Interactively walk a previous run's denials (CLI-19). TTY-required.
    /// No `--json` flag (D-23: review is interactive only).
    Review {
        run_uuid: Option<String>,
    },
    /// List detected persistence-write events (M003-S05).
    Persistence {
        /// Filter to a specific run_uuid.
        run_uuid: Option<String>,
        #[arg(long)] json: bool,
    },
}
