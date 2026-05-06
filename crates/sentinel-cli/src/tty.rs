//! Phase 3 plan 03-09 — TTY detection helper.
use std::io::IsTerminal;

pub fn stdin_is_tty() -> bool { std::io::stdin().is_terminal() }
pub fn stdout_is_tty() -> bool { std::io::stdout().is_terminal() }
pub fn stderr_is_tty() -> bool { std::io::stderr().is_terminal() }
