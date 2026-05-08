//! crates/sentinel-cli/src/install/drift.rs
//!
//! Phase 07 plan 02 — drift detection for D-19 idempotent re-apply.
//! Pure filesystem checks; no daemon round-trip. Mirrors the
//! `SENTINEL_SKIP_LAUNCHCTL` env gate from `launchagent::launchctl_bootstrap`
//! (Pitfall 3): when set, the launchctl-loaded check is skipped so CI
//! runners (no GUI session) don't always report Drifted.
//!
//! Symbol-name notes (vs. plan draft):
//!   - The plan referenced `launchagent::SERVICE_LABEL` and
//!     `launchagent::build_plist_bytes()`. Actual symbols are
//!     `launchagent::LABEL` and `launchagent::build_plist`. The latter
//!     returns `plist::Value`; we compare via `PartialEq` on the
//!     parsed Value (more robust than byte-equality, which would be
//!     fragile across plist serializer whitespace differences).
//!   - The plan's `detect_launchagent()` had no parameters; the actual
//!     content check needs `(daemon_binary, state_dir)` to reconstruct
//!     the canonical plist (which embeds both paths). We thread them
//!     through. Callers in Plan 03's `setup` apply path already have
//!     these values from `resolve_daemon_binary()` + the `state_dir`
//!     argument.

use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

use crate::install::{init_script, launchagent, marker_block};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ComponentState {
    /// Present on disk and content matches canonical.
    Converged,
    /// Present on disk but content/SHA does not match canonical.
    Drifted { reason: String },
    /// Absent on disk.
    Missing,
}

/// LaunchAgent plist + launchctl-loaded check. Honors `SENTINEL_SKIP_LAUNCHCTL`
/// (Pitfall 3): when set, skip the launchctl call and treat plist-existence
/// + content-match as `Converged`.
///
/// Inputs: `daemon_binary` is the absolute path the plist is expected to
/// invoke (typically resolved via `install::resolve_daemon_binary()`);
/// `state_dir` is the daemon's `--state-dir` argument. Both are needed to
/// reconstruct the canonical plist for parsed-`Value` comparison.
pub fn detect_launchagent(daemon_binary: &Path, state_dir: &Path) -> ComponentState {
    let plist = launchagent::plist_path();
    if !plist.exists() {
        return ComponentState::Missing;
    }
    // Read on-disk plist and parse to plist::Value.
    let on_disk = match plist::Value::from_file(&plist) {
        Ok(v) => v,
        Err(e) => {
            return ComponentState::Drifted {
                reason: format!("read/parse {}: {e}", plist.display()),
            };
        }
    };
    let canonical = launchagent::build_plist(daemon_binary, state_dir);
    if on_disk != canonical {
        return ComponentState::Drifted {
            reason: "plist content differs from canonical".into(),
        };
    }
    // Optional launchctl-loaded check (skipped under SENTINEL_SKIP_LAUNCHCTL).
    if std::env::var_os("SENTINEL_SKIP_LAUNCHCTL").is_some() {
        return ComponentState::Converged;
    }
    let uid = unsafe { libc::getuid() };
    let label = launchagent::LABEL;
    let target = format!("gui/{uid}/{label}");
    let status = std::process::Command::new("launchctl")
        .args(["print", &target])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status();
    match status {
        Ok(s) if s.success() => ComponentState::Converged,
        Ok(s) => ComponentState::Drifted {
            reason: format!("launchctl print {target} exit={:?}", s.code()),
        },
        Err(e) => ComponentState::Drifted {
            reason: format!("launchctl spawn: {e}"),
        },
    }
}

/// One ComponentState per rc file Sentinel manages. `Missing` if the rc has
/// no BEGIN_MARKER block; `Converged` if the block's SHA matches canonical;
/// `Drifted` if present-but-different.
pub fn detect_marker_blocks() -> Vec<(PathBuf, ComponentState)> {
    let canonical = marker_block::canonical_block_sha256();
    marker_block::detect_rc_files()
        .into_iter()
        .map(|rc| {
            let state = match std::fs::read_to_string(&rc) {
                Ok(content) => match extract_block(&content) {
                    Some(block) => {
                        let sha = format!("{:x}", Sha256::digest(block.as_bytes()));
                        if sha == canonical {
                            ComponentState::Converged
                        } else {
                            ComponentState::Drifted {
                                reason: format!(
                                    "marker block sha {} != canonical {}",
                                    &sha[..12],
                                    &canonical[..12]
                                ),
                            }
                        }
                    }
                    None => ComponentState::Missing,
                },
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => ComponentState::Missing,
                Err(e) => ComponentState::Drifted {
                    reason: format!("read {}: {e}", rc.display()),
                },
            };
            (rc, state)
        })
        .collect()
}

/// Extract the marker block (BEGIN..END inclusive, plus trailing newline) from
/// rc content. Returns the canonical-format block string for hashing; `None`
/// if no block is present.
fn extract_block(content: &str) -> Option<String> {
    let begin = content.find(marker_block::BEGIN_MARKER)?;
    let rest = &content[begin..];
    let end_rel = rest.find(marker_block::END_MARKER)?;
    let end_abs = begin + end_rel + marker_block::END_MARKER.len();
    // Find the trailing newline after END_MARKER (canonical block ends "\n").
    let after_end_newline = content[end_abs..]
        .find('\n')
        .map(|n| end_abs + n + 1)
        .unwrap_or(end_abs);
    Some(content[begin..after_end_newline].to_string())
}

/// Init script SHA check.
pub fn detect_init_script() -> ComponentState {
    let path = init_script::init_script_path();
    let on_disk = match std::fs::read(&path) {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return ComponentState::Missing,
        Err(e) => {
            return ComponentState::Drifted {
                reason: format!("read {}: {e}", path.display()),
            };
        }
    };
    let canonical = format!(
        "{:x}",
        Sha256::digest(init_script::INIT_SCRIPT_BODY.as_bytes())
    );
    let actual = format!("{:x}", Sha256::digest(&on_disk));
    if actual == canonical {
        ComponentState::Converged
    } else {
        ComponentState::Drifted {
            reason: format!(
                "init_script sha {} != canonical {}",
                &actual[..12],
                &canonical[..12]
            ),
        }
    }
}

/// State dir existence-only check (these are user data; content-hashing would
/// be wrong per RESEARCH.md §"Drift detection").
pub fn detect_state_dir(state_dir: &Path) -> ComponentState {
    if state_dir.is_dir() {
        ComponentState::Converged
    } else {
        ComponentState::Missing
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn extract_block_returns_none_when_no_markers() {
        let content = "echo hello\nexport PATH=/usr/bin\n";
        assert!(extract_block(content).is_none());
    }

    #[test]
    fn extract_block_returns_canonical_when_present() {
        let content = format!(
            "echo hi\n{}\n{}{}\nexport PATH=/usr/bin\n",
            marker_block::BEGIN_MARKER,
            marker_block::STUB_BODY,
            marker_block::END_MARKER
        );
        let extracted = extract_block(&content).unwrap();
        assert!(extracted.contains(marker_block::BEGIN_MARKER));
        assert!(extracted.contains(marker_block::END_MARKER));
    }

    #[test]
    fn detect_state_dir_missing_for_absent_path() {
        let dir = tempdir().unwrap();
        let absent = dir.path().join("does_not_exist");
        assert_eq!(detect_state_dir(&absent), ComponentState::Missing);
    }

    #[test]
    fn detect_state_dir_converged_for_existing_dir() {
        let dir = tempdir().unwrap();
        assert_eq!(detect_state_dir(dir.path()), ComponentState::Converged);
    }

    #[test]
    fn detect_init_script_missing_when_absent() {
        // detect_init_script reads from init_script::init_script_path() which
        // is HOME-relative. Override HOME to a tempdir so the test runs in
        // isolation.
        let dir = tempdir().unwrap();
        // SAFETY: single-purpose test; HOME is read by `home_dir()` only.
        let original_home = std::env::var_os("HOME");
        unsafe { std::env::set_var("HOME", dir.path()) };
        let state = detect_init_script();
        // Restore HOME.
        match original_home {
            Some(h) => unsafe { std::env::set_var("HOME", h) },
            None => unsafe { std::env::remove_var("HOME") },
        }
        assert_eq!(state, ComponentState::Missing);
    }
}
