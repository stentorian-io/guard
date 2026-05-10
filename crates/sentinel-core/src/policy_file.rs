//! `.sentinel.toml` deserde types and parser.
//!
//! D-39 schema:
//!   version = 1
//!
//!   [[rules]]
//!   kind = "allow" | "deny"
//!   match = "exact" | "suffix" | "ip"
//!   pattern = "..."
//!   reason = "..."   # REQUIRED — serde errors on missing
//!
//! `reason` is non-optional by design (D-39): missing reason → parse error →
//! file effectively rejected. Plan 02-03 layers the trust check on top of this
//! parser; the parsed value here is "syntactically valid" but not yet "trusted".

use crate::allowlist::{MatchType, RuleKind};
use serde::Deserialize;
use std::path::{Path, PathBuf};

#[derive(Debug, Deserialize)]
pub struct SentinelToml {
    pub version: u16,
    #[serde(default)]
    pub rules: Vec<PolicyRule>,
}

#[derive(Debug, Deserialize)]
pub struct PolicyRule {
    pub kind: RuleKind,
    #[serde(rename = "match")]
    pub match_type: MatchType,
    pub pattern: String,
    pub reason: String, // REQUIRED — no Option<>; missing reason produces a serde error
}

#[derive(Debug, thiserror::Error)]
pub enum PolicyFileError {
    #[error("toml parse error: {0}")]
    ParseError(String),
    #[error("unsupported version {0}; only version=1 is accepted")]
    UnsupportedVersion(u16),
}

/// Parse a `.sentinel.toml` content string into a SentinelToml.
/// Validates `version == 1` after deserialization.
pub fn parse(content: &str) -> Result<SentinelToml, PolicyFileError> {
    let parsed: SentinelToml =
        toml::from_str(content).map_err(|e| PolicyFileError::ParseError(e.to_string()))?;
    if parsed.version != 1 {
        return Err(PolicyFileError::UnsupportedVersion(parsed.version));
    }
    Ok(parsed)
}

/// Phase 2 D-36 walk boundary: maximum directory levels to search above cwd.
///
/// Phase 07 plan 02: lifted from `sentinel-daemon::policy_file` so the CLI
/// can reuse the walker (`approve --project`, `status review`, first-trust
/// pre-check) without depending on the daemon crate.
pub const MAX_DEPTH: usize = 8;

/// Walk up from `start`, stopping at the first `.sentinel.toml` OR `.git`
/// encountered, depth-capped at MAX_DEPTH. Returns the canonicalized path of
/// the .sentinel.toml or None.
///
/// Symlink handling: `canonicalize()` resolves symlinks once at the start;
/// subsequent `.parent()` operates on the canonical filesystem tree, so
/// symlink loops cannot drive infinite walks. The returned path is also
/// canonicalized via `toml_candidate.canonicalize()` so the caller can
/// compare it against `trusted_policy_files.path` (which stores canonical
/// paths) without further normalization.
///
/// Phase 07 plan 02: lifted verbatim from `sentinel-daemon::policy_file`
/// (D-22 / Q12 walk-up reuse). Behaviorally identical to the prior daemon
/// implementation; daemon callers continue to reach the symbol via the
/// `pub use sentinel_core::policy_file::{find_sentinel_toml, MAX_DEPTH}`
/// re-export in `sentinel-daemon::policy_file`.
pub fn find_sentinel_toml(start: &Path) -> Option<PathBuf> {
    let canonical_start = start.canonicalize().ok()?;
    let mut current = canonical_start.clone();
    // WR-04: stop the walk at $HOME to prevent a hostile prepare script from
    // planting ~/.sentinel.toml (which would be found when the project has no
    // .git boundary in its parent chain). If the user runs sentinel directly
    // from $HOME, that directory IS the start and is still checked.
    let home_boundary = std::env::var_os("HOME")
        .and_then(|h| PathBuf::from(h).canonicalize().ok());
    for _ in 0..MAX_DEPTH {
        // WR-04: if we've walked up to $HOME (and it's not the starting
        // directory), stop — don't find ~/.sentinel.toml planted by a
        // hostile prepare script running in a subdirectory.
        if current != canonical_start {
            if let Some(ref home) = home_boundary {
                if &current == home {
                    return None;
                }
            }
        }
        let toml_candidate = current.join(".sentinel.toml");
        if toml_candidate.exists() {
            return toml_candidate.canonicalize().ok();
        }
        let git_candidate = current.join(".git");
        if git_candidate.exists() {
            return None; // D-36 boundary: .git stops the walk
        }
        match current.parent() {
            Some(p) => current = p.to_owned(),
            None => break,
        }
    }
    None
}

#[cfg(test)]
mod find_sentinel_toml_tests {
    use super::{find_sentinel_toml, MAX_DEPTH};
    use tempfile::tempdir;

    #[test]
    fn finds_in_cwd() {
        let dir = tempdir().unwrap();
        std::fs::write(dir.path().join(".sentinel.toml"), "version = 1\n").unwrap();
        let found = find_sentinel_toml(dir.path()).unwrap();
        assert_eq!(found.file_name().unwrap(), ".sentinel.toml");
    }

    #[test]
    fn returns_none_at_git_boundary() {
        let outer = tempdir().unwrap();
        let inner = outer.path().join("project");
        std::fs::create_dir(&inner).unwrap();
        // .git is a sibling of `inner` candidate parent — placed AT inner so
        // walking up from inner immediately hits the .git boundary on the
        // FIRST iteration before we reach `outer`'s .sentinel.toml.
        std::fs::create_dir(inner.join(".git")).unwrap();
        std::fs::write(outer.path().join(".sentinel.toml"), "version = 1\n").unwrap();
        assert!(find_sentinel_toml(&inner).is_none());
    }

    #[test]
    fn max_depth_is_8() {
        assert_eq!(MAX_DEPTH, 8);
    }

    /// WR-04: the walk must NOT cross $HOME. A .sentinel.toml planted
    /// at $HOME by a hostile prepare script is unreachable when the project
    /// is in a subdirectory.
    #[test]
    fn stops_at_home_boundary() {
        let fake_home = tempdir().unwrap();
        let project = fake_home.path().join("projects").join("myapp");
        std::fs::create_dir_all(&project).unwrap();
        std::fs::write(
            fake_home.path().join(".sentinel.toml"),
            "version = 1\n",
        )
        .unwrap();
        let saved_home = std::env::var_os("HOME");
        // SAFETY: test is single-threaded for this env manipulation.
        unsafe { std::env::set_var("HOME", fake_home.path()) };
        let result = find_sentinel_toml(&project);
        if let Some(ref h) = saved_home {
            unsafe { std::env::set_var("HOME", h) };
        }
        assert!(
            result.is_none(),
            "WR-04: walk must stop at $HOME and not find .sentinel.toml there"
        );
    }
}
