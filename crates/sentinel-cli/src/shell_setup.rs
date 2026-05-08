//! crates/sentinel-cli/src/shell_setup.rs

use std::path::Path;

use crate::install::{artifacts, marker_block};
use crate::CliError;

const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Phase 07 plan 05 (Rule 1 fix): take `state_dir` as a parameter rather
/// than recomputing it via `default_state_dir()` (which ignores the
/// `SENTINEL_STATE_DIR` env override). Bare `setup` writes `state_dir/sentinel.db`
/// via `apply_daemon` and then calls `apply_shell`/`run_shell_setup`; the
/// hardcoded HOME-based default broke that hand-off in tempdir test harnesses
/// where `SENTINEL_STATE_DIR` is the source of truth.
pub fn run_shell_setup(state_dir: &Path) -> Result<i32, CliError> {
    let db_path = state_dir.join("sentinel.db");
    if !db_path.exists() {
        return Err(CliError::Other(
            "sentinel install must run before shell-setup (no install_artifacts DB found)".into()
        ));
    }
    let rc_files = marker_block::detect_rc_files();
    let mut added = 0;
    for rc in rc_files {
        let body = std::fs::read_to_string(&rc).unwrap_or_default();
        if body.contains(marker_block::BEGIN_MARKER) { continue; }
        let canonical = marker_block::install(&rc).map_err(|e| CliError::Other(format!("marker: {e}")))?;
        artifacts::record_artifact(&db_path, "marker_block", &canonical.display().to_string(),
                                    Some(&marker_block::canonical_block_sha256()), VERSION)?;
        println!("  marked {}", rc.display());
        added += 1;
    }
    println!("Added {added} marker block(s).");
    Ok(0)
}
