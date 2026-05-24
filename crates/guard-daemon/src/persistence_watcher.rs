//! Daemon-side persistence-path watcher using kqueue EVFILT_VNODE.
//!
//! Monitors macOS persistence directories (LaunchAgents, LaunchDaemons,
//! crontabs, periodic scripts, shell profiles) for file writes. When a write
//! lands during an active `stt-guard wrap` session, the watcher emits a
//! `gap_kind="persistence-write"` GapRecord to the log writer.
//!
//! This replaces the hook-side open()/openat() interpose that was disabled on
//! macOS 26+ due to dyld init-order crashes (commit 6db0e25).

use crate::log_writer::{GapRecord, JSONL_SCHEMA_VERSION, LogRow, LogWriter, ProcessCtxLog};
use crate::tracked::ProcessTree;
use guard_os::fs_watch::{WatchEvent, WatchSet, open_dir_for_events};
use guard_os::process::process_path;
use std::collections::HashMap;
use std::os::unix::io::RawFd;
use std::path::PathBuf;
use std::sync::Arc;
use tracing::{debug, error, info};

const THREAD_NAME: &str = guard_core::paths::THREAD_PERSIST_WATCH;

/// Spawn the persistence-watcher thread. Returns the join handle (caller
/// typically drops it — the thread runs for the daemon's lifetime).
pub fn spawn_watcher(
    process_tree: Arc<ProcessTree>,
    log_writer: LogWriter,
) -> std::io::Result<std::thread::JoinHandle<()>> {
    std::thread::Builder::new()
        .name(THREAD_NAME.into())
        .spawn(move || {
            if let Err(e) = run_watcher(process_tree, log_writer) {
                error!(error = %e, "persistence watcher exited with error");
            }
        })
}

/// Directories to monitor. Each entry is (path, category).
fn persistence_dirs() -> Vec<(PathBuf, &'static str)> {
    let mut dirs = Vec::new();

    if let Some(home) = std::env::var_os("HOME").map(PathBuf::from) {
        let la = home.join("Library").join("LaunchAgents");
        if la.is_dir() {
            dirs.push((la, "launch-agent"));
        }

        // Shell profiles: watch the home directory itself for writes to
        // dotfiles. We filter by filename in the event handler.
        if home.is_dir() {
            dirs.push((home.clone(), "shell-profile"));
        }

        // macOS 13+ login items
        let btm = home
            .join("Library")
            .join("Application Support")
            .join("com.apple.backgroundtaskmanagementagent");
        if btm.is_dir() {
            dirs.push((btm, "login-item"));
        }
    }

    let system_la = PathBuf::from("/Library/LaunchAgents");
    if system_la.is_dir() {
        dirs.push((system_la, "launch-agent"));
    }

    let system_ld = PathBuf::from("/Library/LaunchDaemons");
    if system_ld.is_dir() {
        dirs.push((system_ld, "launch-daemon"));
    }

    for cron_dir in &["/usr/lib/cron/tabs", "/var/at/tabs"] {
        let p = PathBuf::from(cron_dir);
        if p.is_dir() {
            dirs.push((p, "crontab"));
        }
    }

    for period_dir in &[
        "/etc/periodic/daily",
        "/etc/periodic/weekly",
        "/etc/periodic/monthly",
        "/usr/local/etc/periodic",
    ] {
        let p = PathBuf::from(period_dir);
        if p.is_dir() {
            dirs.push((p, "periodic-script"));
        }
    }

    dirs
}

/// Also watch these directories during `stt-guard wrap` if they get created
/// after initial scan. Called on the 30s timeout to pick up newly-created
/// directories (e.g. ~/Library/LaunchAgents/ created by a package script).
fn persistence_dirs_with_create() -> Vec<(PathBuf, &'static str)> {
    let mut dirs = Vec::new();
    if let Some(home) = std::env::var_os("HOME").map(PathBuf::from) {
        let la = home.join("Library").join("LaunchAgents");
        dirs.push((la, "launch-agent"));
    }
    dirs
}

/// Shell profile filenames that trigger detection when the home directory
/// receives a write event.
const SHELL_PROFILES: &[&str] = &[
    ".bash_profile",
    ".bashrc",
    ".zshrc",
    ".zshenv",
    ".profile",
    ".zprofile",
];

fn is_shell_profile(name: &str) -> bool {
    SHELL_PROFILES.iter().any(|&p| p == name)
}

struct WatchedDir {
    fd: RawFd,
    path: PathBuf,
    category: &'static str,
    baseline: HashMap<String, std::time::SystemTime>,
}

impl Drop for WatchedDir {
    fn drop(&mut self) {
        unsafe { libc::close(self.fd) };
    }
}

fn scan_dir(path: &PathBuf) -> HashMap<String, std::time::SystemTime> {
    let mut map = HashMap::new();
    if let Ok(entries) = std::fs::read_dir(path) {
        for entry in entries.flatten() {
            if let Ok(name) = entry.file_name().into_string() {
                if let Ok(meta) = entry.metadata() {
                    if let Ok(mtime) = meta.modified() {
                        map.insert(name, mtime);
                    }
                }
            }
        }
    }
    map
}

/// Best-effort process attribution: check which tracked PID wrote a file
/// by looking for a PID that is still alive and was recently active.
/// Returns (pid, pidversion, binary_path) if a tracked process can be
/// identified as the likely writer.
///
/// This is inherently racy — the writing process may have already exited
/// by the time kqueue delivers the event. The fallback (pid=0) still
/// records the persistence-write event; the target path itself is the
/// primary forensic signal.
fn attribute_write(process_tree: &ProcessTree) -> (u32, u32, String) {
    let pids = process_tree.list_tracked_pids();
    for (pid, pidversion) in &pids {
        // Verify the process is still alive.
        let ret = unsafe { libc::kill(*pid as i32, 0) };
        if ret != 0 {
            continue;
        }
        if let Some(binary) = process_path(*pid as libc::pid_t) {
            return (*pid, *pidversion, binary);
        }
        return (*pid, *pidversion, String::new());
    }
    (0, 0, String::new())
}

fn run_watcher(process_tree: Arc<ProcessTree>, log_writer: LogWriter) -> std::io::Result<()> {
    let dirs = persistence_dirs();
    if dirs.is_empty() {
        info!("no persistence directories found to watch");
        return Ok(());
    }

    let mut watch_set = match WatchSet::new() {
        Ok(watch_set) => watch_set,
        Err(err) => {
            info!(error = %err, "persistence watcher unsupported");
            return Ok(());
        }
    };

    let mut watched: Vec<WatchedDir> = Vec::new();

    for (path, category) in &dirs {
        if let Some(w) = open_watch(path, category) {
            watched.push(w);
        }
    }

    if watched.is_empty() {
        info!("no persistence directories could be opened for watching");
        return Ok(());
    }

    register_watches(&watch_set, &watched)?;

    info!(dirs = watched.len(), "persistence watcher started");

    let mut fd_to_idx: HashMap<RawFd, usize> =
        watched.iter().enumerate().map(|(i, w)| (w.fd, i)).collect();

    loop {
        let event = match watch_set.wait(30) {
            Ok(event) => event,
            Err(err) => {
                error!(error = %err, "filesystem watch wait failed");
                break;
            }
        };

        // On timeout (n==0), try to pick up newly-created directories.
        let event_fds = match event {
            WatchEvent::Timeout => {
                for (path, category) in persistence_dirs_with_create() {
                    if fd_to_idx.values().any(|&idx| watched[idx].path == path) {
                        continue;
                    }
                    if let Some(w) = open_watch(&path, category) {
                        let new_idx = watched.len();
                        let new_fd = w.fd;
                        watched.push(w);
                        fd_to_idx.insert(new_fd, new_idx);
                        if let Err(err) = watch_set.add(new_fd) {
                            error!(error = %err, path = %path.display(), "failed to add persistence dir watch");
                        }
                        info!(path = %path.display(), "added new persistence dir watch");
                    }
                }
                continue;
            }
            WatchEvent::Fds(fds) if fds.is_empty() => continue,
            WatchEvent::Fds(fds) => fds,
        };

        let active_runs = process_tree.list_runs();
        if active_runs.is_empty() {
            // No active runs — update baselines silently.
            for fd in &event_fds {
                if let Some(&idx) = fd_to_idx.get(fd) {
                    watched[idx].baseline = scan_dir(&watched[idx].path);
                }
            }
            continue;
        }

        for fd in &event_fds {
            let idx = match fd_to_idx.get(fd) {
                Some(&i) => i,
                None => continue,
            };

            let w = &mut watched[idx];
            let new_scan = scan_dir(&w.path);

            for (name, mtime) in &new_scan {
                if w.category == "shell-profile" && !is_shell_profile(name) {
                    continue;
                }

                let is_new_or_modified = match w.baseline.get(name) {
                    None => true,
                    Some(old_mtime) => mtime > old_mtime,
                };

                if !is_new_or_modified {
                    continue;
                }

                let full_path = w.path.join(name);
                let full_path_str = full_path.to_string_lossy().to_string();

                let (pid, pidversion, binary) = attribute_write(&process_tree);

                let run_uuid = active_runs
                    .first()
                    .map(|r| r.run_uuid.clone())
                    .unwrap_or_default();

                let gap = GapRecord {
                    schema_version: JSONL_SCHEMA_VERSION,
                    ts: crate::log_writer::now_rfc3339(),
                    run_uuid,
                    gap_kind: "persistence-write",
                    process: ProcessCtxLog {
                        pid,
                        pidversion,
                        argv: if binary.is_empty() {
                            vec![]
                        } else {
                            vec![binary]
                        },
                        cwd: String::new(),
                    },
                    binary_path: Some(full_path_str.clone()),
                };

                info!(
                    path = %full_path_str,
                    category = w.category,
                    pid,
                    "persistence write detected"
                );

                log_writer.send(LogRow::Gap(gap));
            }

            w.baseline = new_scan;
        }
    }

    Ok(())
}

fn open_watch(path: &PathBuf, category: &'static str) -> Option<WatchedDir> {
    let fd = match open_dir_for_events(path) {
        Ok(fd) => fd,
        Err(err) => {
            debug!(path = %path.display(), error = %err, "cannot open persistence dir for watching");
            return None;
        }
    };
    let baseline = scan_dir(path);
    Some(WatchedDir {
        fd,
        path: path.clone(),
        category,
        baseline,
    })
}

fn register_watches(watch_set: &WatchSet, watched: &[WatchedDir]) -> std::io::Result<()> {
    watch_set
        .add_many(watched.iter().map(|w| w.fd))
        .map_err(std::io::Error::other)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shell_profile_match() {
        assert!(is_shell_profile(".zshrc"));
        assert!(is_shell_profile(".bashrc"));
        assert!(is_shell_profile(".bash_profile"));
        assert!(is_shell_profile(".profile"));
        assert!(is_shell_profile(".zshenv"));
        assert!(is_shell_profile(".zprofile"));
        assert!(!is_shell_profile(".vimrc"));
        assert!(!is_shell_profile("README.md"));
    }

    #[test]
    fn persistence_dirs_returns_some_dirs() {
        let dirs = persistence_dirs();
        if std::env::var_os("HOME").is_some() {
            assert!(!dirs.is_empty(), "expected at least one persistence dir");
        }
    }

    #[test]
    fn scan_dir_on_nonexistent_returns_empty() {
        let map = scan_dir(&PathBuf::from("/nonexistent-path-abc123"));
        assert!(map.is_empty());
    }

    #[test]
    fn scan_dir_on_tmp() {
        let tmp = std::env::temp_dir();
        let map = scan_dir(&tmp);
        // /tmp should have some entries; just verify it doesn't crash.
        let _ = map;
    }
}
