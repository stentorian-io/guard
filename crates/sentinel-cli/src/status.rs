//! crates/sentinel-cli/src/status.rs
//!
//! Phase 3 plan 03-10 — `sentinel status` (CLI-02, D-69..D-72).

use std::path::Path;

use sentinel_ipc::{DaemonStateKind, GapInfo, StatusCounters, StatusReply, TrackedRootInfo, InstallInfo};

use crate::CliError;

const ONE_DAY_MS: u64 = 24 * 60 * 60 * 1000;

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
                render_verbose(daemon_state, &tracked_roots, &recent_gaps, &counters, install_info.as_ref());
            } else {
                render_minimal(daemon_state, recent_count_24h);
            }
            Ok(0)
        }
    }
}

fn render_offline(state: DaemonStateKind, verbose: bool, json: bool) -> Result<i32, CliError> {
    if json {
        let payload = serde_json::json!({
            "daemon_state": match state {
                DaemonStateKind::NotInstalled => "NotInstalled",
                DaemonStateKind::DaemonNotRunning => "DaemonNotRunning",
                _ => "Unknown",
            }
        });
        println!("{}", payload);
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
        render_verbose(state, &[], &[], &zero_counters, None);
    } else {
        render_minimal(state, 0);
    }
    Ok(2)
}

fn render_minimal(state: DaemonStateKind, gaps_24h: usize) {
    match state {
        DaemonStateKind::Operational => println!("sentinel: operational"),
        DaemonStateKind::Degraded => println!(
            "sentinel: degraded — {gaps_24h} coverage gap(s) in last 24h. Run `sentinel status --verbose` for detail."
        ),
        DaemonStateKind::StaleFeeds => {
            println!("sentinel: stale-feeds — feeds older than threshold. (Phase 4 reserved.)")
        }
        DaemonStateKind::DaemonNotRunning => println!(
            "sentinel: daemon-not-running — run `launchctl bootstrap gui/$(id -u) ~/Library/LaunchAgents/com.sentinel.daemon.plist`"
        ),
        DaemonStateKind::NotInstalled => println!("sentinel: not-installed — run `sentinel install`"),
    }
}

fn render_verbose(
    state: DaemonStateKind,
    tracked_roots: &[TrackedRootInfo],
    recent_gaps: &[GapInfo],
    counters: &StatusCounters,
    install_info: Option<&InstallInfo>,
) {
    let state_str = match state {
        DaemonStateKind::Operational => "operational",
        DaemonStateKind::Degraded => "degraded",
        DaemonStateKind::StaleFeeds => "stale-feeds",
        DaemonStateKind::DaemonNotRunning => "daemon-not-running",
        DaemonStateKind::NotInstalled => "not-installed",
    };
    println!("State: {state_str}");
    if let Some(info) = install_info {
        println!("Version: {} (installed_at_ms {})", info.version, info.installed_at_ms);
        println!("Artifacts:");
        for a in &info.artifacts {
            println!("  {:<14} {}", a.artifact_kind, a.target_path);
        }
    } else {
        println!("Install info: (none)");
    }
    println!("\nCounters:");
    println!("  rules_user:         {}", counters.rules_user);
    println!("  rules_trusted_toml: {}", counters.rules_trusted_toml);
    println!("  blocks_today:       {}", counters.blocks_today);
    println!("  allows_today:       {}", counters.allows_today);
    println!("  gaps_today:         {}", counters.gaps_today);

    println!("\nTracked roots ({}):", tracked_roots.len());
    for r in tracked_roots {
        println!("  run_uuid={} argv={:?}", r.run_uuid, r.argv);
    }
    println!("\nRecent gaps ({}):", recent_gaps.len());
    for g in recent_gaps {
        println!(
            "  {} {} {}",
            g.gap_kind,
            g.run_uuid,
            g.binary_path.as_deref().unwrap_or("-")
        );
    }
}
