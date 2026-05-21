//! clap derive structs for the `stt-guard` CLI.

use clap::{Parser, Subcommand};
use std::ffi::OsString;

#[derive(Parser, Debug)]
#[command(
    name = "stt-guard",
    version,
    about = "Default-deny outbound network enforcement for wrapped commands",
    long_about = "\
Stentorian Guard sandboxes outbound network egress from a command and its children.

USAGE:
  sudo stt-guard init                         One-time hardened setup (requires root)

  stt-guard wrap <cmd> [args...]              Wrap a command under enforcement
  stt-guard wrap --learn <cmd> [args...]      Record unknown destinations as user rules
                                             (TTY required; fails clear in non-TTY)

  stt-guard status [logs|rules|denials|review|persistence|advisory]
                                             Inspect daemon health, rules, denials
  stt-guard status advisory <ID>              Look up threat-intel advisory details

  sudo stt-guard install                      Hardened install: _sentinel service user,
                                             root-owned binaries, LaunchDaemon
  sudo stt-guard uninstall                    Reverse a hardened install
"
)]
pub struct Cli {
    #[command(subcommand)]
    pub cmd: Cmd,
}

#[derive(Subcommand, Debug)]
pub enum Cmd {
    /// Initialise Stentorian Guard (hardened mode). Requires root.
    ///
    /// Creates the _stt_guard service user, deploys root-owned binaries,
    /// and starts the daemon as a LaunchDaemon.
    Init {
        /// Skip interactive confirmation.
        #[arg(short = 'y', long)]
        yes: bool,
    },

    /// Wrap a command under default-deny network enforcement.
    Wrap {
        /// Observe unknown destinations and present them for review after the
        /// run. Curated-deny and confirmed intel threats still block; suspect
        /// intel prompts interactively. TTY required.
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

    /// Hardened system install: create _sentinel service user, set root
    /// ownership on binaries, install LaunchDaemon, and transfer runtime
    /// state to _sentinel. Requires root (run with sudo).
    Install,

    /// Reverse a previous `stt-guard install`: stop the LaunchDaemon,
    /// remove the _sentinel service user, and restore user-mode paths.
    /// Requires root (run with sudo).
    Uninstall,
}

/// Status read sub-verbs.
#[derive(Subcommand, Debug)]
pub enum StatusSub {
    /// Stream the JSONL forensic log (pipe to `tail -f` for follow mode).
    Logs,
    /// List active rules. Use --disable/--enable to manage built-in rules.
    Rules {
        /// Include built-in registry-allowlist rules.
        #[arg(long)]
        include_built_in: bool,

        /// Disable a built-in rule by pattern (e.g. "registry.npmjs.org").
        /// Use when a trusted source is compromised. Requires --reason.
        #[arg(long, requires = "reason")]
        disable: Option<String>,

        /// Re-enable a previously disabled built-in rule by pattern.
        #[arg(long, conflicts_with = "disable")]
        enable: Option<String>,

        /// Reason for disabling (required with --disable).
        #[arg(long, requires = "disable")]
        reason: Option<String>,
    },
    /// View denials from a specific run_uuid.
    Denials { run_uuid: String },
    /// Interactively walk a previous run's denials. TTY-required.
    Review { run_uuid: Option<String> },
    /// List detected persistence-write events.
    Persistence {
        /// Filter to a specific run_uuid.
        run_uuid: Option<String>,
    },
    /// Look up details for a threat-intel advisory ID (e.g. MAL-2025-3008).
    Advisory { advisory_id: String },
}
