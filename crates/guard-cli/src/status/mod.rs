//! crates/guard-cli/src/status/mod.rs
//!
//! v0.3 — `stt-guard status`.
//! render_* refactored to pub(crate) _to variants for unit testing.
//!
//! v0.7 — converted from a leaf `status.rs` file into a `status/` directory
//! with submodules for the new `stt-guard status <noun>` verbs (`rules`,
//! `trust`, `denials`, `review`).

pub mod advisory;
pub mod denials;
pub mod persistence;
pub mod review;
pub mod rules;

use std::path::Path;

use guard_ipc::{
    DaemonStateKind, GapInfo, InstallInfo, StatusCounters, StatusReply, TrackedRootInfo,
};

use crate::CliError;

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

pub fn run_status(sock: &Path, state_dir: &Path) -> Result<i32, CliError> {
    let reply = crate::ipc_client::status_request(sock)?;

    match reply {
        StatusReply::Err { message, .. } => {
            eprintln!("stt-guard: error — {message}");
            Ok(2)
        }
        StatusReply::Ok {
            daemon_state,
            tracked_roots,
            recent_gaps,
            counters,
            install_info,
            ..
        } => {
            render_verbose(
                daemon_state,
                &tracked_roots,
                &recent_gaps,
                &counters,
                install_info.as_ref(),
            );
            render_risk_exposure(sock);
            if let Some(wd) = read_watchdog_health(state_dir) {
                render_watchdog_health(&wd);
            }
            Ok(0)
        }
    }
}

pub fn render_verbose(
    state: DaemonStateKind,
    tracked_roots: &[TrackedRootInfo],
    recent_gaps: &[GapInfo],
    counters: &StatusCounters,
    install_info: Option<&InstallInfo>,
) {
    render_verbose_to(
        &mut std::io::stdout().lock(),
        state,
        tracked_roots,
        recent_gaps,
        counters,
        install_info,
    );
}

pub fn render_verbose_to<W: std::io::Write>(
    w: &mut W,
    state: DaemonStateKind,
    tracked_roots: &[TrackedRootInfo],
    recent_gaps: &[GapInfo],
    counters: &StatusCounters,
    install_info: Option<&InstallInfo>,
) {
    let state_str = match state {
        DaemonStateKind::Operational => "operational",
        DaemonStateKind::Degraded => "degraded",
    };
    let _ = writeln!(w, "State: {state_str}");
    if let Some(info) = install_info {
        let _ = writeln!(
            w,
            "Version: {} (installed_at_ms {})",
            info.version, info.installed_at_ms
        );
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

pub fn render_risk_exposure(sock: &Path) {
    render_risk_exposure_to(&mut std::io::stdout().lock(), sock);
}

pub fn render_risk_exposure_to<W: std::io::Write>(w: &mut W, sock: &Path) {
    use guard_core::RuleTier;

    let curated = match guard_daemon::curated::load_curated() {
        Ok(entries) => entries,
        Err(_) => return,
    };
    let user_rules = match crate::ipc_client::list_rules_request(sock, false) {
        Ok(rules) => rules,
        Err(_) => return,
    };

    let user_allows: Vec<_> = user_rules.iter().filter(|r| r.kind == "allow").collect();

    if user_allows.is_empty() {
        return;
    }

    let mut exposed = Vec::new();
    for ua in &user_allows {
        for ce in &curated {
            if !matches!(ce.tier, RuleTier::ConfirmedDeny | RuleTier::SuspectDeny) {
                continue;
            }
            if ce.pattern == ua.pattern {
                let confidence = match ce.tier {
                    RuleTier::ConfirmedDeny => "CONFIRMED",
                    RuleTier::SuspectDeny => "suspect",
                    _ => "unknown",
                };
                exposed.push((ua.pattern.clone(), confidence, ce.reason.clone()));
            }
        }
    }

    if exposed.is_empty() {
        return;
    }

    let _ = writeln!(
        w,
        "\n\x1b[33mRisk exposure ({} user-approved rule(s) overlap with threat intel):\x1b[0m",
        exposed.len()
    );
    for (pattern, confidence, reason) in &exposed {
        let _ = writeln!(w, "  {pattern} [{confidence}] — {reason}");
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
    use guard_ipc::DaemonStateKind;

    fn empty_counters() -> StatusCounters {
        StatusCounters {
            rules_user: 0,
            blocks_today: 0,
            allows_today: 0,
            gaps_today: 0,
        }
    }

    #[test]
    fn render_verbose_emits_correct_state_string() {
        let cases: &[(DaemonStateKind, &str)] = &[
            (DaemonStateKind::Operational, "State: operational"),
            (DaemonStateKind::Degraded, "State: degraded"),
        ];

        for (state, expected_first_line) in cases {
            let mut buf = Vec::new();
            render_verbose_to(&mut buf, *state, &[], &[], &empty_counters(), None);
            let s = String::from_utf8(buf).unwrap();
            let first_line = s.lines().next().unwrap_or("");
            assert_eq!(
                first_line, *expected_first_line,
                "render_verbose_to({:?}): first line mismatch",
                state
            );
        }
    }
}
