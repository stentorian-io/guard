//! v0.3 — sentinel logs --follow stays connected across rotation.
//!
//! R-02 mitigation verification: the notify-based tail in logs_follow.rs
//! reopens the file handle when a rename (rotation) is detected, so --follow
//! streams rows from the new active file without the user needing to restart.
//!
//! Test strategy:
//!   1. Seed sentinel.log with a known "pre-rotation" row.
//!   2. Spawn `sentinel logs --follow` subprocess.
//!   3. Wait for it to see the first row.
//!   4. Manually "rotate": rename sentinel.log → sentinel-YYYYMMDD.log + create
//!      a new empty sentinel.log.
//!   5. Append a "post-rotation" row to the new file.
//!   6. Wait 2s for the watcher to detect the rename and reopen.
//!   7. Kill --follow; assert both rows appear in its stdout.
//!
//! Marked #[ignore]: requires daemon harness + 2s wall-clock wait; opt-in via
//!   cargo test -p sentinel-e2e -- --ignored follow_streams

#[cfg(target_os = "macos")]
#[test]
#[ignore = "long-running (2s wall-clock); rotation requires file rename; opt-in via --ignored"]
fn follow_streams_across_rotation() {
    let harness = sentinel_e2e::DaemonHarness::start().expect("start daemon harness");
    let cli = sentinel_e2e::resolve_cli();
    let log_dir = harness.home.path().join("Library/Logs/Sentinel");
    let log_path = log_dir.join("sentinel.log");
    std::fs::create_dir_all(&log_dir).expect("create log dir");

    // Seed sentinel.log with a pre-rotation row.
    std::fs::write(
        &log_path,
        b"{\"event\":\"allow\",\"ts\":\"2026-05-08T12:00:00.000Z\",\"dest_host\":\"pre_rotation_marker\"}\n",
    )
    .expect("write seed row");

    // Spawn `sentinel status logs --follow` (was: `sentinel logs --follow`).
    // v0.7: `logs --follow` → `status logs --follow`.
    let mut follow = std::process::Command::new(&cli)
        .arg("status")
        .arg("logs")
        .arg("--follow")
        .env_clear()
        .env("HOME", harness.home.path())
        .env("PATH", std::env::var_os("PATH").unwrap_or_default())
        .env("SENTINEL_STATE_DIR", &harness.state_dir)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("spawn sentinel status logs --follow");

    // Allow --follow to open the file and read the initial row.
    std::thread::sleep(std::time::Duration::from_millis(500));

    // Append a second "pre-rotation" row.
    use std::io::Write as _;
    {
        let mut f = std::fs::OpenOptions::new()
            .append(true)
            .open(&log_path)
            .expect("open log for append");
        writeln!(
            f,
            r#"{{"event":"block","ts":"2026-05-08T12:00:01.000Z","dest_host":"pre_rotation_block"}}"#
        )
        .expect("write block row");
    }
    std::thread::sleep(std::time::Duration::from_millis(300));

    // Force rotation: rename active log → archived name, create new empty active log.
    let rotated = log_dir.join("sentinel-20260508-001.log");
    std::fs::rename(&log_path, &rotated).expect("rename (simulate rotation)");
    std::fs::write(&log_path, b"").expect("create new active log file");

    // Append a post-rotation row to the new active file.
    {
        let mut f = std::fs::OpenOptions::new()
            .append(true)
            .open(&log_path)
            .expect("open new log for append");
        writeln!(
            f,
            r#"{{"event":"allow","ts":"2026-05-08T12:00:02.000Z","dest_host":"post_rotation_marker"}}"#
        )
        .expect("write post-rotation row");
    }

    // Allow the notify watcher (+ 1s stat-fallback) to detect the rename and reopen.
    std::thread::sleep(std::time::Duration::from_millis(2500));

    // Kill --follow and collect stdout.
    let _ = follow.kill();
    let out = follow.wait_with_output().expect("wait for --follow exit");
    let stdout = String::from_utf8_lossy(&out.stdout);

    assert!(
        stdout.contains("pre_rotation_block"),
        "pre-rotation row missing from --follow output;\nstdout: {stdout}"
    );
    assert!(
        stdout.contains("post_rotation_marker"),
        "post-rotation row missing — --follow stopped streaming after rotation;\nstdout: {stdout}"
    );
}
