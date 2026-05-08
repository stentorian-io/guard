//! clap derive structs for the `sentinel` CLI (Phase 07 redesign — D-09 hard-cut, 2-verb shape).

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
  sentinel <cmd> [args...]            Wrap a command under enforcement
  sentinel --learn <cmd> [args...]    Record unknown destinations to .sentinel.toml
                                      (TTY required; fails clear in non-TTY)

  sentinel setup [daemon|shell] [--remove|--reinstall] [-y]
                                      Install / repair / remove components
  sentinel status [logs|rules|trust|denials|review] [--follow|--all|--project|--json]
                                      Inspect daemon health, rules, trust, denials

To wrap a binary whose name collides with a Sentinel verb, pass its full path:
  sentinel /usr/local/bin/status
"
)]
pub struct Cli {
    /// Auto-allow unknown destinations and record them to .sentinel.toml.
    /// TTY required; refuses to run in non-interactive environments.
    #[arg(long, global = false)]
    pub learn: bool,

    #[command(subcommand)]
    pub cmd: Cmd,
}

#[derive(Subcommand, Debug)]
pub enum Cmd {
    /// Install / repair / remove daemon and shell components (CLI-11..CLI-13).
    Setup {
        #[command(subcommand)]
        target: Option<SetupTarget>,
        /// Remove the targeted component(s) instead of installing.
        #[arg(long, conflicts_with = "reinstall")]
        remove: bool,
        /// Force-clean reinstall: wipe + re-derive (D-16/D-17).
        #[arg(long, conflicts_with = "remove")]
        reinstall: bool,
        /// Skip TTY confirmation prompts (D-18). `--force` is NOT a synonym.
        #[arg(long, short = 'y')]
        yes: bool,
    },

    /// Inspect daemon health, rules, trust, denials (CLI-14..CLI-19).
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

    /// (Default) Wrap a command under enforcement.
    /// `argv[0]` is the binary name; subsequent elements are passed verbatim.
    #[command(external_subcommand)]
    External(Vec<OsString>),
}

/// Per-target setup dispatch (D-15).
#[derive(Subcommand, Debug, Clone, Copy, PartialEq, Eq)]
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
}
