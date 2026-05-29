//! `stt-guard status advisory <ID>` — look up threat-intel advisory details.

use crate::CliError;
use guard_daemon::curated;

/// Print curated rule entries that reference an advisory id.
///
/// # Errors
///
/// Returns an error when curated rules cannot be loaded.
pub fn run(advisory_id: &str) -> Result<i32, CliError> {
    let entries = curated::load_curated()
        .map_err(|e| CliError::Other(format!("failed to load curated rules: {e}")))?;

    let matches: Vec<_> = entries
        .iter()
        .filter(|e| e.reason.contains(advisory_id))
        .collect();

    if matches.is_empty() {
        eprintln!("No entries found for advisory {advisory_id}");
        return Ok(1);
    }

    println!("Advisory: {advisory_id}");
    println!("Matching rules ({}):", matches.len());
    println!();
    for e in &matches {
        println!("  tier:    {:?}", e.tier);
        println!("  match:   {:?} {}", e.match_type, e.pattern);
        println!("  reason:  {}", e.reason);
        println!();
    }

    Ok(0)
}
