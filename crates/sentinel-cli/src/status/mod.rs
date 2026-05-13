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
pub mod trust;

use std::path::Path;

use sentinel_ipc::{DaemonStateKind, FeedInfo, GapInfo, StatusCounters, StatusReply, TrackedRootInfo, InstallInfo};

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
    let reply = match crate::ipc_client::probe_daemon_alive(sock) {
        Ok(()) => match crate::ipc_client::status_request(sock) {
            Ok(r) => r,
            Err(_) => {
                let db = state_dir.join("sentinel.db");
                return render_offline(
                    if db.exists() { DaemonStateKind::DaemonNotRunning } else { DaemonStateKind::NotInstalled },
                    verbose,
                    json,
                );
            }
        },
        Err(_) => {
            let db = state_dir.join("sentinel.db");
            return render_offline(
                if db.exists() { DaemonStateKind::DaemonNotRunning } else { DaemonStateKind::NotInstalled },
                verbose,
                json,
            );
        }
    };

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

pub(crate) fn render_offline(state: DaemonStateKind, verbose: bool, json: bool) -> Result<i32, CliError> {
    render_offline_to(&mut std::io::stdout().lock(), state, verbose, json)
}

pub(crate) fn render_offline_to<W: std::io::Write>(
    w: &mut W,
    state: DaemonStateKind,
    verbose: bool,
    json: bool,
) -> Result<i32, CliError> {
    if json {
        let payload = serde_json::json!({
            "daemon_state": match state {
                DaemonStateKind::NotInstalled => "NotInstalled",
                DaemonStateKind::DaemonNotRunning => "DaemonNotRunning",
                _ => "Unknown",
            }
        });
        let _ = writeln!(w, "{}", payload);
        return Ok(2);
    }
    let zero_counters = StatusCounters {
        rules_user: 0,
        rules_trusted_toml: 0,
        blocks_today: 0,
        allows_today: 0,
        gaps_today: 0,
    };
    if verbose {
        render_verbose_to(w, state, &[], &[], &zero_counters, &[], None);
    } else {
        render_minimal_to(w, state, 0, &[]);
    }
    Ok(2)
}

pub(crate) fn render_minimal(state: DaemonStateKind, gaps_24h: usize, feeds: &[FeedInfo]) {
    render_minimal_to(&mut std::io::stdout().lock(), state, gaps_24h, feeds);
}

pub(crate) fn render_minimal_to<W: std::io::Write>(w: &mut W, state: DaemonStateKind, gaps_24h: usize, feeds: &[FeedInfo]) {
    let ambient = std::env::var_os("SENTINEL_AMBIENT").is_some();
    match state {
        DaemonStateKind::Operational => {
            if ambient {
                let _ = writeln!(w, "sentinel: operational (ambient shell wrapping active)");
            } else {
                let _ = writeln!(w, "sentinel: operational");
            }
        }
        DaemonStateKind::Degraded => { let _ = writeln!(
            w,
            "sentinel: degraded — {gaps_24h} coverage gap(s) in last 24h. Run `sentinel status --verbose` for detail."
        ); }
        DaemonStateKind::StaleFeeds => {
            let stale_names: Vec<&str> = feeds.iter().filter(|f| !f.fresh).map(|f| f.name.as_str()).collect();
            if stale_names.is_empty() {
                let _ = writeln!(w, "sentinel: stale-feeds — threat-intel feeds older than 7 days. Run `sentinel run` to refresh.");
            } else {
                let _ = writeln!(
                    w,
                    "sentinel: stale-feeds — {} older than 7 days. Run `sentinel run` to refresh.",
                    stale_names.join(", ")
                );
            }
        }
        DaemonStateKind::DaemonNotRunning => { let _ = writeln!(
            w,
            "sentinel: daemon-not-running — run `launchctl bootstrap gui/$(id -u) ~/Library/LaunchAgents/com.sentinel.daemon.plist`"
        ); }
        DaemonStateKind::NotInstalled => { let _ = writeln!(w, "sentinel: not-installed — run `sentinel install`"); }
    }
}

pub(crate) fn render_verbose(
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

pub(crate) fn render_verbose_to<W: std::io::Write>(
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
        DaemonStateKind::DaemonNotRunning => "daemon-not-running",
        DaemonStateKind::NotInstalled => "not-installed",
    };
    let _ = writeln!(w, "State: {state_str}");
    if std::env::var_os("SENTINEL_AMBIENT").is_some() {
        let _ = writeln!(w, "Ambient: active (shell wrapping enabled)");
    }
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
    let _ = writeln!(w, "  rules_user:         {}", counters.rules_user);
    let _ = writeln!(w, "  rules_trusted_toml: {}", counters.rules_trusted_toml);
    let _ = writeln!(w, "  blocks_today:       {}", counters.blocks_today);
    let _ = writeln!(w, "  allows_today:       {}", counters.allows_today);
    let _ = writeln!(w, "  gaps_today:         {}", counters.gaps_today);

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

    /// Test 1: render_minimal_to emits state-specific content for all 5 variants.
    #[test]
    fn render_minimal_emits_correct_line_for_each_state() {
        let cases: &[(DaemonStateKind, &[&str])] = &[
            (DaemonStateKind::NotInstalled, &["not-installed", "sentinel install"]),
            (DaemonStateKind::DaemonNotRunning, &["daemon-not-running", "launchctl"]),
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

    /// Test 2: render_minimal_to includes gap count for Degraded state.
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

    /// Test 3: render_verbose_to emits "State: <state-string>" as the first line for all 5 variants.
    #[test]
    fn render_verbose_emits_correct_state_string() {
        let cases: &[(DaemonStateKind, &str)] = &[
            (DaemonStateKind::Operational, "State: operational"),
            (DaemonStateKind::Degraded, "State: degraded"),
            (DaemonStateKind::StaleFeeds, "State: stale-feeds"),
            (DaemonStateKind::DaemonNotRunning, "State: daemon-not-running"),
            (DaemonStateKind::NotInstalled, "State: not-installed"),
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

    /// Test 5: render_minimal_to shows stale feed names when available.
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

    /// Test 6: render_verbose_to includes Feeds section.
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

    /// Test 4: render_offline_to with json=true emits correct "daemon_state" discriminator.
    #[test]
    fn render_offline_json_emits_correct_discriminator() {
        // NotInstalled
        let mut buf = Vec::new();
        render_offline_to(&mut buf, DaemonStateKind::NotInstalled, false, true)
            .expect("render_offline_to NotInstalled json");
        let s = String::from_utf8(buf).unwrap();
        let v: serde_json::Value = serde_json::from_str(s.trim()).expect("valid JSON for NotInstalled");
        assert_eq!(
            v.get("daemon_state").and_then(|x| x.as_str()),
            Some("NotInstalled"),
            "NotInstalled json: got: {v}"
        );

        // DaemonNotRunning
        let mut buf2 = Vec::new();
        render_offline_to(&mut buf2, DaemonStateKind::DaemonNotRunning, false, true)
            .expect("render_offline_to DaemonNotRunning json");
        let s2 = String::from_utf8(buf2).unwrap();
        let v2: serde_json::Value = serde_json::from_str(s2.trim()).expect("valid JSON for DaemonNotRunning");
        assert_eq!(
            v2.get("daemon_state").and_then(|x| x.as_str()),
            Some("DaemonNotRunning"),
            "DaemonNotRunning json: got: {v2}"
        );
    }
}
