//! Phase 3 plan 03-16 (gap closure for UAT item #1) — Tier A artifact-only
//! install/uninstall round-trip. Runs by default in `cargo test`; the
//! launchctl bootstrap step is short-circuited via SENTINEL_SKIP_LAUNCHCTL=1
//! (plan 03-15 env gate). Real-launchctl coverage lives in the Tier B sibling
//! file install_uninstall_launchd.rs (cfg(feature = "ci-launchd")).
//!
//! Closes UAT item #1 from .planning/phases/03-cli-surface-ux-forensic-logging/
//! 03-VERIFICATION.md.

use std::io::Write as _;
use std::process::{Command, Stdio};

use sentinel_e2e::{cargo_target_dir, resolve_cli};

#[cfg(target_os = "macos")]
#[test]
fn install_writes_all_artifacts_then_uninstall_removes_them() {
    let home = tempfile::tempdir().expect("home tempdir");
    let state_tmp = tempfile::Builder::new()
        .prefix(".se2e16")
        .tempdir_in("/tmp")
        .expect("state_dir tempdir");
    let state_dir = state_tmp.path().to_path_buf();

    let cli = resolve_cli();
    let daemon_bin = cargo_target_dir().join("sentineld");
    if !daemon_bin.exists() {
        panic!("sentineld binary not found at {} — run cargo build first", daemon_bin.display());
    }

    // --- INSTALL ---
    let mut child = Command::new(&cli)
        .arg("install").arg("--no-shell-integration")
        .env_clear()
        .env("HOME", home.path())
        .env("PATH", std::env::var_os("PATH").unwrap_or_default())
        .env("SENTINEL_DAEMON_BINARY", &daemon_bin)
        .env("SENTINEL_STATE_DIR", &state_dir)
        .env("SENTINEL_SKIP_LAUNCHCTL", "1")
        .stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped())
        .spawn().expect("spawn sentinel install");
    if let Some(mut stdin) = child.stdin.take() {
        let _ = stdin.write_all(b"y\n");
    }
    let install_out = child.wait_with_output().expect("install wait");
    assert!(install_out.status.success(),
        "install failed: status={:?} stdout={} stderr={}",
        install_out.status.code(),
        String::from_utf8_lossy(&install_out.stdout),
        String::from_utf8_lossy(&install_out.stderr));

    let plist = home.path().join("Library/LaunchAgents/com.sentinel.daemon.plist");
    let init_sh = home.path().join(".config/sentinel/init.sh");
    let db = state_dir.join("sentinel.db");
    assert!(plist.exists(), "plist missing: {}", plist.display());
    assert!(init_sh.exists(), "init.sh missing: {}", init_sh.display());
    assert!(db.exists(), "sentinel.db missing: {}", db.display());

    // Assert install_artifacts rows.
    let conn = rusqlite::Connection::open(&db).expect("open db");
    let mut stmt = conn.prepare("SELECT artifact_kind FROM install_artifacts").expect("prepare");
    let kinds: Vec<String> = stmt
        .query_map([], |r| r.get::<_, String>(0))
        .expect("query")
        .filter_map(|r| r.ok())
        .collect();
    assert!(kinds.iter().any(|k| k == "launchagent"), "no launchagent row: {kinds:?}");
    assert!(kinds.iter().any(|k| k == "init_script"), "no init_script row: {kinds:?}");
    assert!(kinds.iter().any(|k| k == "state_dir"), "no state_dir row: {kinds:?}");
    assert!(kinds.iter().any(|k| k == "log_dir"), "no log_dir row: {kinds:?}");
    drop(stmt); drop(conn);

    // --- UNINSTALL ---
    let uninstall_out = Command::new(&cli)
        .arg("uninstall").arg("--force")
        .env_clear()
        .env("HOME", home.path())
        .env("PATH", std::env::var_os("PATH").unwrap_or_default())
        .env("SENTINEL_STATE_DIR", &state_dir)
        .env("SENTINEL_SKIP_LAUNCHCTL", "1")
        .output().expect("uninstall wait");
    assert!(uninstall_out.status.success(),
        "uninstall failed: status={:?} stdout={} stderr={}",
        uninstall_out.status.code(),
        String::from_utf8_lossy(&uninstall_out.stdout),
        String::from_utf8_lossy(&uninstall_out.stderr));

    assert!(!plist.exists(), "plist still present after uninstall");
    assert!(!init_sh.exists(), "init.sh still present after uninstall");
    assert!(!state_dir.exists(), "state_dir still present after uninstall");
    let log_dir = home.path().join("Library/Logs/Sentinel");
    assert!(!log_dir.exists(), "log_dir still present after uninstall");
}

#[cfg(target_os = "macos")]
#[test]
fn install_with_shell_integration_writes_marker_blocks() {
    let home = tempfile::tempdir().expect("home tempdir");
    let state_tmp = tempfile::Builder::new()
        .prefix(".se2e16b")
        .tempdir_in("/tmp")
        .expect("state_dir tempdir");
    let state_dir = state_tmp.path().to_path_buf();

    // Pre-create rc files so install detects them.
    let zshrc = home.path().join(".zshrc");
    let bashrc = home.path().join(".bashrc");
    std::fs::write(&zshrc, b"# pre-existing zshrc\n").unwrap();
    std::fs::write(&bashrc, b"# pre-existing bashrc\n").unwrap();

    let cli = resolve_cli();
    let daemon_bin = cargo_target_dir().join("sentineld");

    let mut child = Command::new(&cli)
        .arg("install")  // shell integration enabled (default)
        .env_clear()
        .env("HOME", home.path())
        .env("PATH", std::env::var_os("PATH").unwrap_or_default())
        .env("SENTINEL_DAEMON_BINARY", &daemon_bin)
        .env("SENTINEL_STATE_DIR", &state_dir)
        .env("SENTINEL_SKIP_LAUNCHCTL", "1")
        .stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped())
        .spawn().expect("spawn sentinel install");
    if let Some(mut stdin) = child.stdin.take() {
        let _ = stdin.write_all(b"y\n");
    }
    let install_out = child.wait_with_output().expect("install wait");
    assert!(install_out.status.success(),
        "install failed; stderr: {}", String::from_utf8_lossy(&install_out.stderr));

    let zshrc_after = std::fs::read_to_string(&zshrc).unwrap();
    let bashrc_after = std::fs::read_to_string(&bashrc).unwrap();
    assert!(zshrc_after.contains("# >>> sentinel >>>"), "zshrc missing marker: {zshrc_after}");
    assert!(zshrc_after.contains("# <<< sentinel <<<"), "zshrc missing closing marker");
    assert!(bashrc_after.contains("# >>> sentinel >>>"), "bashrc missing marker: {bashrc_after}");

    // Assert 2 marker_block rows in install_artifacts.
    let db = state_dir.join("sentinel.db");
    let conn = rusqlite::Connection::open(&db).expect("open db");
    let count: i64 = conn.query_row(
        "SELECT count(*) FROM install_artifacts WHERE artifact_kind = 'marker_block'",
        [], |r| r.get(0)
    ).expect("count marker_block rows");
    assert_eq!(count, 2, "expected exactly 2 marker_block rows, got {count}");
    drop(conn);

    // Uninstall, assert markers stripped.
    let uninstall_out = Command::new(&cli)
        .arg("uninstall").arg("--force")
        .env_clear()
        .env("HOME", home.path())
        .env("PATH", std::env::var_os("PATH").unwrap_or_default())
        .env("SENTINEL_STATE_DIR", &state_dir)
        .env("SENTINEL_SKIP_LAUNCHCTL", "1")
        .output().expect("uninstall wait");
    assert!(uninstall_out.status.success(),
        "uninstall failed: stderr={}", String::from_utf8_lossy(&uninstall_out.stderr));

    let zshrc_final = std::fs::read_to_string(&zshrc).unwrap();
    let bashrc_final = std::fs::read_to_string(&bashrc).unwrap();
    assert!(!zshrc_final.contains("# >>> sentinel >>>"),
        "zshrc still has marker after uninstall: {zshrc_final}");
    assert!(!bashrc_final.contains("# >>> sentinel >>>"),
        "bashrc still has marker after uninstall");
}
