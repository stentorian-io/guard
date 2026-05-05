//! clap derive structs for the `sentinel` CLI. (RED stub — filled in GREEN)
use clap::{Parser, Subcommand};
use std::ffi::OsString;

#[derive(Parser, Debug)]
#[command(name = "sentinel", version, about = "Default-deny outbound network enforcement for wrapped commands")]
pub struct Cli {
    #[command(subcommand)]
    pub cmd: Cmd,
}

#[derive(Subcommand, Debug)]
pub enum Cmd {
    /// Wrap and execute a command under default-deny network enforcement.
    Run {
        #[arg(trailing_var_arg = true, allow_hyphen_values = true, num_args = 1..)]
        command: Vec<OsString>,
    },
}
