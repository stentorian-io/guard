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

  sentinel status [logs|rules|denials|review|persistence|advisory]
                                             Inspect daemon health, rules, denials
  sentinel status advisory <ID>              Look up threat-intel advisory details
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
    },

    /// Manage curated (built-in) rules.
    Rules {
        #[command(subcommand)]
        sub: RulesSub,
    },
}

/// Rules management sub-verbs.
#[derive(Subcommand, Debug)]
pub enum RulesSub {
    /// Disable a curated (built-in) rule by pattern.
    /// Use when a trusted source is compromised.
    Disable {
        /// The rule pattern to disable (e.g. "registry.npmjs.org").
        pattern: String,

        /// Reason for disabling (e.g. "suspected compromise 2026-05-20").
        #[arg(long)]
        reason: String,
    },
    /// Re-enable a previously disabled curated rule.
    Enable {
        /// The rule pattern to re-enable.
        pattern: String,
    },
}

/// Status read sub-verbs.
#[derive(Subcommand, Debug)]
pub enum StatusSub {
    /// Stream the JSONL forensic log (pipe to `tail -f` for follow mode).
    Logs,
    /// List active rules.
    Rules {
        /// Include built-in registry-allowlist rules.
        #[arg(long)]
        include_built_in: bool,
    },
    /// View denials from a specific run_uuid.
    Denials {
        run_uuid: String,
    },
    /// Interactively walk a previous run's denials. TTY-required.
    Review {
        run_uuid: Option<String>,
    },
    /// List detected persistence-write events.
    Persistence {
        /// Filter to a specific run_uuid.
        run_uuid: Option<String>,
    },
    /// Look up details for a threat-intel advisory ID (e.g. MAL-2025-3008).
    Advisory {
        advisory_id: String,
    },
}
