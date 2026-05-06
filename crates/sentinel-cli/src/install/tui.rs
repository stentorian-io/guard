//! crates/sentinel-cli/src/install/tui.rs
//!
//! Phase 3 plan 03-09 — interactive package-manager picker (D-61).

use std::io::IsTerminal;

use dialoguer::{theme::ColorfulTheme, MultiSelect};

pub const PACKAGE_MANAGERS: &[&str] = &[
    "npm", "pnpm", "yarn", "pip", "pip3", "pipx",
    "cargo", "bundle", "gem", "go", "mix", "hex", "composer",
];

/// Probe PATH for known package-manager binaries.
pub fn detect_package_managers() -> Vec<&'static str> {
    PACKAGE_MANAGERS.iter().copied()
        .filter(|name| which_check(name))
        .collect()
}

fn which_check(name: &str) -> bool {
    let path = match std::env::var_os("PATH") {
        Some(p) => p,
        None => return false,
    };
    for dir in std::env::split_paths(&path) {
        let candidate = dir.join(name);
        if candidate.is_file() { return true; }
    }
    false
}

/// MultiSelect picker (Pitfall 7 fallback: non-TTY → yes-to-all).
pub fn pick_aliases(detected: &[&str]) -> std::io::Result<Vec<usize>> {
    if !std::io::stdin().is_terminal() {
        // D-61 fallback: select all.
        return Ok((0..detected.len()).collect());
    }
    let defaults: Vec<bool> = vec![true; detected.len()];
    MultiSelect::with_theme(&ColorfulTheme::default())
        .with_prompt("Wrap which package managers? (space=toggle, a=all, n=none, enter=submit)")
        .items(detected)
        .defaults(&defaults)
        .interact()
        .map_err(|e| std::io::Error::other(format!("dialoguer: {e}")))
}
