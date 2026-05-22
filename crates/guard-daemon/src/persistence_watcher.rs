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
        // Get the binary path via proc_pidpath.
        let mut buf = [0u8; libc::MAXPATHLEN as usize];
        let n = unsafe {
            libc::proc_pidpath(
                *pid as i32,
                buf.as_mut_ptr() as *mut libc::c_void,
                buf.len() as u32,
            )
        };
        if n > 0 {
            let binary = String::from_utf8_lossy(&buf[..n as usize]).to_string();
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

    let kq = unsafe { libc::kqueue() };
    if kq < 0 {
        return Err(std::io::Error::last_os_error());
    }

    let mut watched: Vec<WatchedDir> = Vec::new();

    for (path, category) in &dirs {
        if let Some(w) = open_watch(path, category) {
            watched.push(w);
        }
    }

    if watched.is_empty() {
        info!("no persistence directories could be opened for watching");
        unsafe { libc::close(kq) };
        return Ok(());
    }

    register_watches(kq, &watched)?;

    info!(dirs = watched.len(), "persistence watcher started");

    let mut fd_to_idx: HashMap<RawFd, usize> =
        watched.iter().enumerate().map(|(i, w)| (w.fd, i)).collect();

    let mut eventlist = vec![unsafe { std::mem::zeroed::<libc::kevent>() }; 16];

    loop {
        let timeout = libc::timespec {
            tv_sec: 30,
            tv_nsec: 0,
        };
        let n = unsafe {
            libc::kevent(
                kq,
                std::ptr::null(),
                0,
                eventlist.as_mut_ptr(),
                eventlist.len() as i32,
                &timeout,
            )
        };

        if n < 0 {
            let err = std::io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            error!(error = %err, "kevent wait failed");
            break;
        }

        // On timeout (n==0), try to pick up newly-created directories.
        if n == 0 {
            for (path, category) in persistence_dirs_with_create() {
                if fd_to_idx.values().any(|&idx| watched[idx].path == path) {
                    continue;
                }
                if let Some(w) = open_watch(&path, category) {
                    let new_idx = watched.len();
                    let new_fd = w.fd;
                    watched.push(w);
                    fd_to_idx.insert(new_fd, new_idx);
                    // Register the new fd with kqueue.
                    let kev = libc::kevent {
                        ident: new_fd as usize,
                        filter: libc::EVFILT_VNODE,
                        flags: libc::EV_ADD | libc::EV_CLEAR,
                        fflags: libc::NOTE_WRITE | libc::NOTE_EXTEND,
                        data: 0,
                        udata: std::ptr::null_mut(),
                    };
                    unsafe {
                        libc::kevent(kq, &kev, 1, std::ptr::null_mut(), 0, std::ptr::null());
                    }
                    info!(path = %path.display(), "added new persistence dir watch");
                }
            }
            continue;
        }

        let active_runs = process_tree.list_runs();
        if active_runs.is_empty() {
            // No active runs — update baselines silently.
            for i in 0..(n as usize) {
                let ev = &eventlist[i];
                if let Some(&idx) = fd_to_idx.get(&(ev.ident as RawFd)) {
                    watched[idx].baseline = scan_dir(&watched[idx].path);
                }
            }
            continue;
        }

        for i in 0..(n as usize) {
            let ev = &eventlist[i];
            let idx = match fd_to_idx.get(&(ev.ident as RawFd)) {
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

    unsafe { libc::close(kq) };
    Ok(())
}

fn open_watch(path: &PathBuf, category: &'static str) -> Option<WatchedDir> {
    let c_path = std::ffi::CString::new(path.to_string_lossy().as_bytes()).ok()?;
    let fd = unsafe { libc::open(c_path.as_ptr(), libc::O_RDONLY | libc::O_EVTONLY) };
    if fd < 0 {
        debug!(path = %path.display(), "cannot open persistence dir for watching");
        return None;
    }
    let baseline = scan_dir(path);
    Some(WatchedDir {
        fd,
        path: path.clone(),
        category,
        baseline,
    })
}

fn register_watches(kq: RawFd, watched: &[WatchedDir]) -> std::io::Result<()> {
    let changelist: Vec<libc::kevent> = watched
        .iter()
        .map(|w| libc::kevent {
            ident: w.fd as usize,
            filter: libc::EVFILT_VNODE,
            flags: libc::EV_ADD | libc::EV_CLEAR,
            fflags: libc::NOTE_WRITE | libc::NOTE_EXTEND,
            data: 0,
            udata: std::ptr::null_mut(),
        })
        .collect();

    let ret = unsafe {
        libc::kevent(
            kq,
            changelist.as_ptr(),
            changelist.len() as i32,
            std::ptr::null_mut(),
            0,
            std::ptr::null(),
        )
    };
    if ret < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
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
