//! crates/sentinel-cli/src/status/mod.rs
//!
//! Phase 3 plan 03-10 — `sentinel status` (CLI-02, D-69..D-72).
//! Phase 3 plan 03-17 — render_* refactored to pub(crate) _to variants for unit
//! testing (gap-closure UAT #2).
//!
//! Phase 07 plan 03 — converted from a leaf `status.rs` file into a
//! `status/` directory with submodules for the new `sentinel status
//! <noun>` verbs (`rules`, `trust`, `denials`, `review`). The bare-status
//! path (`run_status`) below is preserved verbatim — Plan 04's dispatch
//! arm continues to call `crate::status::run_status` unchanged.

pub mod denials;
pub mod persistence;
pub mod review;
pub mod rules;

use std::path::Path;

use sentinel_ipc::{DaemonStateKind, FeedInfo, GapInfo, InstallInfo, StatusCounters, StatusReply, TrackedRootInfo};

use crate::CliError;

const ONE_DAY_MS: u64 = 24 * 60 * 60 * 1000;

#[derive(Debug, Clone, serde::Deserialize)]
struct WatchdogHealth {
    restart_count: u32,
    last_restart_reason: Option<String>,
    last_restart_epoch: Option<u64>,
    last_restart_latency_ms: Option<u64>,
}

fn read_watchdog_health(state_dir: &Path) -> Option<WatchdogHealth> {
    let path = state_dir.join("watchdog.state");
    let content = std::fs::read_to_string(path).ok()?;
    serde_json::from_str(&content).ok()
}

pub fn run_status(sock: &Path, state_dir: &Path, verbose: bool, json: bool) -> Result<i32, CliError> {
    let _ = state_dir;
    let reply = crate::ipc_client::status_request(sock)?;

    if json {
        let s = serde_json::to_string(&reply).map_err(|e| CliError::Other(format!("json: {e}")))?;
        println!("{s}");
        return Ok(0);
    }
    match reply {
        StatusReply::Err { message, .. } => {
            eprintln!("sentinel: error — {message}");
            Ok(2)
        }
        StatusReply::Ok {
            daemon_state,
            tracked_roots,
            recent_gaps,
            counters,
            feeds,
            install_info,
            ..
        } => {
            // WARNING #6 fix: daemon_state comes from the daemon AS-IS (no CLI promotion).
            // We still compute a 24h gap count for the minimal-default remediation message.
            let now_ms = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_millis() as u64)
                .unwrap_or(0);
            let recent_count_24h = recent_gaps
                .iter()
                .filter(|g| now_ms.saturating_sub(g.detected_at_ms) < ONE_DAY_MS)
                .count();

            if verbose {
                render_verbose(daemon_state, &tracked_roots, &recent_gaps, &counters, &feeds, install_info.as_ref());
                if let Some(wd) = read_watchdog_health(state_dir) {
                    render_watchdog_health(&wd);
                }
            } else {
                render_minimal(daemon_state, recent_count_24h, &feeds);
            }
            Ok(0)
        }
    }
}

pub fn render_minimal(state: DaemonStateKind, gaps_24h: usize, feeds: &[FeedInfo]) {
    render_minimal_to(&mut std::io::stdout().lock(), state, gaps_24h, feeds);
}

pub fn render_minimal_to<W: std::io::Write>(w: &mut W, state: DaemonStateKind, gaps_24h: usize, feeds: &[FeedInfo]) {
    match state {
        DaemonStateKind::Operational => {
            let _ = writeln!(w, "sentinel: operational");
        }
        DaemonStateKind::Degraded => { let _ = writeln!(
            w,
            "sentinel: degraded — {gaps_24h} coverage gap(s) in last 24h. Run `sentinel status --verbose` for detail."
        ); }
        DaemonStateKind::StaleFeeds => {
            let stale_names: Vec<&str> = feeds.iter().filter(|f| !f.fresh).map(|f| f.name.as_str()).collect();
            if stale_names.is_empty() {
                let _ = writeln!(w, "sentinel: stale-feeds — threat-intel feeds older than 7 days. Run `sentinel wrap` to refresh.");
            } else {
                let _ = writeln!(
                    w,
                    "sentinel: stale-feeds — {} older than 7 days. Run `sentinel wrap` to refresh.",
                    stale_names.join(", ")
                );
            }
        }
    }
}

pub fn render_verbose(
    state: DaemonStateKind,
    tracked_roots: &[TrackedRootInfo],
    recent_gaps: &[GapInfo],
    counters: &StatusCounters,
    feeds: &[FeedInfo],
    install_info: Option<&InstallInfo>,
) {
    render_verbose_to(
        &mut std::io::stdout().lock(),
        state,
        tracked_roots,
        recent_gaps,
        counters,
        feeds,
        install_info,
    );
}

pub fn render_verbose_to<W: std::io::Write>(
    w: &mut W,
    state: DaemonStateKind,
    tracked_roots: &[TrackedRootInfo],
    recent_gaps: &[GapInfo],
    counters: &StatusCounters,
    feeds: &[FeedInfo],
    install_info: Option<&InstallInfo>,
) {
    let state_str = match state {
        DaemonStateKind::Operational => "operational",
        DaemonStateKind::Degraded => "degraded",
        DaemonStateKind::StaleFeeds => "stale-feeds",
    };
    let _ = writeln!(w, "State: {state_str}");
    if let Some(info) = install_info {
        let _ = writeln!(w, "Version: {} (installed_at_ms {})", info.version, info.installed_at_ms);
        let _ = writeln!(w, "Artifacts:");
        for a in &info.artifacts {
            let _ = writeln!(w, "  {:<14} {}", a.artifact_kind, a.target_path);
        }
    } else {
        let _ = writeln!(w, "Install info: (none)");
    }
    let _ = writeln!(w, "\nCounters:");
    let _ = writeln!(w, "  rules_user:   {}", counters.rules_user);
    let _ = writeln!(w, "  blocks_today: {}", counters.blocks_today);
    let _ = writeln!(w, "  allows_today: {}", counters.allows_today);
    let _ = writeln!(w, "  gaps_today:   {}", counters.gaps_today);

    let _ = writeln!(w, "\nFeeds ({}):", feeds.len());
    for f in feeds {
        let age_str = match f.last_pulled_at_ms {
            Some(ms) => {
                let now_ms = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_millis() as u64)
                    .unwrap_or(0);
                let age_h = now_ms.saturating_sub(ms) / (60 * 60 * 1000);
                if age_h < 1 {
                    "< 1h ago".to_string()
                } else if age_h < 24 {
                    format!("{age_h}h ago")
                } else {
                    format!("{}d ago", age_h / 24)
                }
            }
            None => "never".to_string(),
        };
        let fresh_str = if f.fresh { "fresh" } else { "STALE" };
        let _ = writeln!(w, "  {:<6} {:<12} ({})", f.name, age_str, fresh_str);
    }

    let _ = writeln!(w, "\nTracked roots ({}):", tracked_roots.len());
    for r in tracked_roots {
        let _ = writeln!(w, "  run_uuid={} argv={:?}", r.run_uuid, r.argv);
    }
    let _ = writeln!(w, "\nRecent gaps ({}):", recent_gaps.len());
    for g in recent_gaps {
        let _ = writeln!(
            w,
            "  {} {} {}",
            g.gap_kind,
            g.run_uuid,
            g.binary_path.as_deref().unwrap_or("-")
        );
    }
}

fn render_watchdog_health(wd: &WatchdogHealth) {
    render_watchdog_health_to(&mut std::io::stdout().lock(), wd);
}

fn render_watchdog_health_to<W: std::io::Write>(w: &mut W, wd: &WatchdogHealth) {
    let _ = writeln!(w, "\nWatchdog:");
    let _ = writeln!(w, "  restart_count:        {}", wd.restart_count);
    if let Some(ref reason) = wd.last_restart_reason {
        let _ = writeln!(w, "  last_restart_reason:  {reason}");
    }
    if let Some(epoch) = wd.last_restart_epoch {
        let _ = writeln!(w, "  last_restart_epoch:   {epoch}");
    }
    if let Some(ms) = wd.last_restart_latency_ms {
        let _ = writeln!(w, "  last_restart_latency: {ms}ms");
    }
}

#[cfg(test)]
mod render_tests {
    use super::*;
    use sentinel_ipc::DaemonStateKind;

    fn empty_counters() -> StatusCounters {
        StatusCounters {
            rules_user: 0,
            rules_trusted_toml: 0,
            blocks_today: 0,
            allows_today: 0,
            gaps_today: 0,
        }
    }

    #[test]
    fn render_minimal_emits_correct_line_for_each_state() {
        let cases: &[(DaemonStateKind, &[&str])] = &[
            (DaemonStateKind::Operational, &["operational"]),
            (DaemonStateKind::Degraded, &["degraded", "coverage gap"]),
            (DaemonStateKind::StaleFeeds, &["stale-feeds", "7 days"]),
        ];

        for (state, expected_substrings) in cases {
            let mut buf = Vec::new();
            render_minimal_to(&mut buf, *state, 0, &[]);
            let s = String::from_utf8(buf).unwrap();
            for expected in *expected_substrings {
                assert!(
                    s.contains(expected),
                    "render_minimal_to({:?}): expected '{}' in output, got: {:?}",
                    state,
                    expected,
                    s
                );
            }
        }
    }

    #[test]
    fn render_minimal_includes_gap_count_for_degraded() {
        let mut buf = Vec::new();
        render_minimal_to(&mut buf, DaemonStateKind::Degraded, 7, &[]);
        let s = String::from_utf8(buf).unwrap();
        assert!(
            s.contains("7 coverage gap"),
            "expected '7 coverage gap' in degraded output, got: {:?}",
            s
        );
    }

    #[test]
    fn render_verbose_emits_correct_state_string() {
        let cases: &[(DaemonStateKind, &str)] = &[
            (DaemonStateKind::Operational, "State: operational"),
            (DaemonStateKind::Degraded, "State: degraded"),
            (DaemonStateKind::StaleFeeds, "State: stale-feeds"),
        ];

        for (state, expected_first_line) in cases {
            let mut buf = Vec::new();
            render_verbose_to(&mut buf, *state, &[], &[], &empty_counters(), &[], None);
            let s = String::from_utf8(buf).unwrap();
            let first_line = s.lines().next().unwrap_or("");
            assert_eq!(
                first_line, *expected_first_line,
                "render_verbose_to({:?}): first line mismatch",
                state
            );
        }
    }

    #[test]
    fn render_minimal_stale_feeds_shows_feed_names() {
        use sentinel_ipc::FeedInfo;
        let feeds = vec![
            FeedInfo { name: "OSV".to_string(), last_pulled_at_ms: Some(100), fresh: false },
            FeedInfo { name: "GHSA".to_string(), last_pulled_at_ms: Some(200), fresh: true },
        ];
        let mut buf = Vec::new();
        render_minimal_to(&mut buf, DaemonStateKind::StaleFeeds, 0, &feeds);
        let s = String::from_utf8(buf).unwrap();
        assert!(s.contains("OSV"), "should mention the stale feed name");
        assert!(!s.contains("GHSA"), "should not mention the fresh feed");
    }

    #[test]
    fn render_verbose_includes_feeds_section() {
        use sentinel_ipc::FeedInfo;
        let feeds = vec![
            FeedInfo { name: "OSV".to_string(), last_pulled_at_ms: None, fresh: false },
        ];
        let mut buf = Vec::new();
        render_verbose_to(&mut buf, DaemonStateKind::Operational, &[], &[], &empty_counters(), &feeds, None);
        let s = String::from_utf8(buf).unwrap();
        assert!(s.contains("Feeds (1):"), "should have Feeds section");
        assert!(s.contains("OSV"), "should list OSV feed");
        assert!(s.contains("never"), "should show 'never' for unpulled feed");
        assert!(s.contains("STALE"), "should show STALE for non-fresh feed");
    }
}
