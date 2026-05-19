//! v0.3 — TTY detection helper.
//!
//! v0.7 — consolidated `confirm` helper. The four pre-existing file-private
//! duplicates in `uninstall.rs`, `install/mod.rs::confirm_yn`, `approve.rs`,
//! and `trust_policy.rs` were removed in this version.
use std::io::IsTerminal;

pub fn stdin_is_tty() -> bool { std::io::stdin().is_terminal() }
pub fn stdout_is_tty() -> bool { std::io::stdout().is_terminal() }
pub fn stderr_is_tty() -> bool { std::io::stderr().is_terminal() }

/// Prompt the user with `[y/N]` confirmation. Refuses non-TTY stdin
/// (`--yes` is the only authorized auto-confirm; piped `yes` on stdin
/// is rejected to prevent accidental destructive auto-agree).
/// Returns true for "y" / "yes" (case-insensitive); false for any other
/// input including bare Enter.
pub fn confirm(prompt: &str) -> Result<bool, crate::CliError> {
    use std::io::{BufRead, Write};
    if !std::io::stdin().is_terminal() {
        return Err(crate::CliError::Other(format!(
            "{prompt} (TTY required for confirmation; pass --yes to skip)"
        )));
    }
    print!("{prompt} [y/N] ");
    std::io::stdout()
        .flush()
        .map_err(|e| crate::CliError::Other(format!("stdout: {e}")))?;
    let mut line = String::new();
    std::io::stdin()
        .lock()
        .read_line(&mut line)
        .map_err(|e| crate::CliError::Other(format!("stdin: {e}")))?;
    Ok(matches!(line.trim().to_lowercase().as_str(), "y" | "yes"))
}
