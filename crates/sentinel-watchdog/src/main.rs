//! sentinel-watchdog: polls the daemon's Unix socket at 500ms intervals
//! and logs liveness state. On 2 consecutive missed pings, escalates:
//! SIGTERM → 200ms grace → SIGKILL. Designed to be run as a LaunchAgent
//! alongside the daemon; launchd KeepAlive=true then restarts the daemon.

use clap::Parser;
use nix::sys::signal::{self, Signal};
use nix::unistd::Pid;
use sentinel_ipc::frame::{read_frame, write_frame};
use sentinel_ipc::{Ping, PingReply};
use socket2::{Domain, SockAddr, Socket, Type};
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tracing::{debug, error, info, warn};

const TAG_PING: u8 = 0x15;
const CONNECT_TIMEOUT: Duration = Duration::from_millis(500);
const IO_TIMEOUT: Duration = Duration::from_millis(500);
const POLL_INTERVAL: Duration = Duration::from_millis(500);
const KILL_THRESHOLD: u32 = 2;
const SIGTERM_GRACE: Duration = Duration::from_millis(200);

#[derive(Parser)]
#[command(name = "sentinel-watchdog", about = "Sentinel daemon watchdog")]
struct Cli {
    #[arg(long, hide = true)]
    state_dir: Option<PathBuf>,
}

fn default_state_dir() -> PathBuf {
    let home = std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/tmp"));
    home.join("Library")
        .join("Application Support")
        .join("Sentinel")
}

fn socket_path(state_dir: &std::path::Path) -> PathBuf {
    state_dir.join("sentineld.sock")
}

fn ready_path(state_dir: &std::path::Path) -> PathBuf {
    state_dir.join("daemon.ready")
}

fn watchdog_state_path(state_dir: &std::path::Path) -> PathBuf {
    state_dir.join("watchdog.state")
}

fn read_daemon_pid(state_dir: &std::path::Path) -> Option<u32> {
    let content = std::fs::read_to_string(ready_path(state_dir)).ok()?;
    let pid_str = content.split_whitespace().next()?;
    pid_str.parse().ok()
}

#[allow(dead_code)]
fn read_daemon_start_epoch(state_dir: &std::path::Path) -> Option<u64> {
    let content = std::fs::read_to_string(ready_path(state_dir)).ok()?;
    let mut parts = content.split_whitespace();
    parts.next()?; // skip pid
    parts.next()?.parse().ok()
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct WatchdogState {
    restart_count: u32,
    last_restart_reason: Option<String>,
    last_restart_epoch: Option<u64>,
    last_restart_latency_ms: Option<u64>,
}

impl WatchdogState {
    fn load(state_dir: &std::path::Path) -> Self {
        std::fs::read_to_string(watchdog_state_path(state_dir))
            .ok()
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or(Self {
                restart_count: 0,
                last_restart_reason: None,
                last_restart_epoch: None,
                last_restart_latency_ms: None,
            })
    }

    fn save(&self, state_dir: &std::path::Path) {
        if let Ok(json) = serde_json::to_string(self) {
            let _ = std::fs::write(watchdog_state_path(state_dir), json);
        }
    }
}

fn kill_escalation(pid: u32) {
    let nix_pid = Pid::from_raw(pid as i32);
    info!(pid, "sending SIGTERM");
    if signal::kill(nix_pid, Signal::SIGTERM).is_err() {
        debug!(pid, "SIGTERM failed (process already gone?)");
        return;
    }
    std::thread::sleep(SIGTERM_GRACE);
    // Check if still alive
    if signal::kill(nix_pid, None).is_ok() {
        warn!(pid, "still alive after SIGTERM grace period, sending SIGKILL");
        let _ = signal::kill(nix_pid, Signal::SIGKILL);
    } else {
        debug!(pid, "process exited after SIGTERM");
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LivenessState {
    Alive { pid: u32, uptime_secs: u64 },
    Unreachable,
}

fn ping_daemon(sock: &std::path::Path) -> LivenessState {
    let addr = match SockAddr::unix(sock) {
        Ok(a) => a,
        Err(_) => return LivenessState::Unreachable,
    };
    let socket = match Socket::new(Domain::UNIX, Type::STREAM, None) {
        Ok(s) => s,
        Err(_) => return LivenessState::Unreachable,
    };
    if socket.connect_timeout(&addr, CONNECT_TIMEOUT).is_err() {
        return LivenessState::Unreachable;
    }
    socket.set_read_timeout(Some(IO_TIMEOUT)).ok();
    socket.set_write_timeout(Some(IO_TIMEOUT)).ok();
    let mut stream: UnixStream = socket.into();

    // Write tag byte
    if stream.write_all(&[TAG_PING]).is_err() {
        return LivenessState::Unreachable;
    }
    // Write CBOR-encoded Ping
    let req = Ping::new();
    if write_frame(&mut stream, &req).is_err() {
        return LivenessState::Unreachable;
    }
    // Read tag echo
    let mut tag_back = [0u8; 1];
    if stream.read_exact(&mut tag_back).is_err() || tag_back[0] != TAG_PING {
        return LivenessState::Unreachable;
    }
    // Read CBOR-encoded PingReply
    let reply: PingReply = match read_frame(&mut stream) {
        Ok(r) => r,
        Err(_) => return LivenessState::Unreachable,
    };
    match reply {
        PingReply::Pong { pid, uptime_secs, .. } => LivenessState::Alive { pid, uptime_secs },
        PingReply::Err { .. } => LivenessState::Unreachable,
    }
}

fn main() {
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let cli = Cli::parse();
    let state_dir = cli.state_dir.unwrap_or_else(default_state_dir);
    let sock = socket_path(&state_dir);

    info!(socket = %sock.display(), poll_ms = POLL_INTERVAL.as_millis(), "watchdog starting");

    let shutdown = Arc::new(AtomicBool::new(false));
    signal_hook::flag::register(signal_hook::consts::SIGTERM, Arc::clone(&shutdown)).ok();
    signal_hook::flag::register(signal_hook::consts::SIGINT, Arc::clone(&shutdown)).ok();

    let mut consecutive_misses: u32 = 0;
    let mut last_state = LivenessState::Unreachable;
    let mut last_known_pid: Option<u32> = read_daemon_pid(&state_dir);
    let mut wd_state = WatchdogState::load(&state_dir);
    let mut kill_triggered_at: Option<Instant> = None;

    while !shutdown.load(Ordering::Relaxed) {
        let start = Instant::now();
        let liveness = ping_daemon(&sock);

        match liveness {
            LivenessState::Alive { pid, uptime_secs } => {
                if last_state == LivenessState::Unreachable {
                    let latency_ms = kill_triggered_at.map(|t| t.elapsed().as_millis() as u64);
                    if let Some(ms) = latency_ms {
                        info!(pid, uptime_secs, latency_ms = ms, "daemon recovered after restart");
                        wd_state.last_restart_latency_ms = Some(ms);
                    } else {
                        info!(pid, uptime_secs, "daemon recovered");
                    }
                    wd_state.restart_count += 1;
                    wd_state.last_restart_reason = Some("watchdog-detected-outage".into());
                    let now_epoch = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs();
                    wd_state.last_restart_epoch = Some(now_epoch);
                    wd_state.save(&state_dir);
                    kill_triggered_at = None;
                } else {
                    debug!(pid, uptime_secs, "daemon alive");
                }
                consecutive_misses = 0;
                last_known_pid = Some(pid);
            }
            LivenessState::Unreachable => {
                consecutive_misses += 1;
                if consecutive_misses == 1 {
                    warn!(consecutive_misses, "daemon unreachable");
                } else if consecutive_misses == KILL_THRESHOLD {
                    if let Some(pid) = read_daemon_pid(&state_dir).or(last_known_pid) {
                        error!(consecutive_misses, pid, "kill threshold reached, escalating");
                        kill_triggered_at = Some(Instant::now());
                        kill_escalation(pid);
                    } else {
                        error!(consecutive_misses, "kill threshold reached but no known PID");
                    }
                } else {
                    error!(consecutive_misses, "daemon still unreachable");
                }
            }
        }

        last_state = liveness;

        let elapsed = start.elapsed();
        if elapsed < POLL_INTERVAL {
            std::thread::sleep(POLL_INTERVAL - elapsed);
        }
    }

    info!("watchdog shutting down");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ping_nonexistent_socket_returns_unreachable() {
        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("no-such.sock");
        assert_eq!(ping_daemon(&sock), LivenessState::Unreachable);
    }
}
