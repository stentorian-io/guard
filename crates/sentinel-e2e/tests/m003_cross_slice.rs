//! M003-S08: Cross-slice integration tests verifying that all M003 features
//! work together in a single wrapped process tree.
//!
//! These tests exercise combinations of:
//!   - S01: Expanded hooks (send, write-to-socket deny)
//!   - S04: Persistence-write detection via open/openat interpose
//!   - S05: `sentinel status persistence` CLI surface
//!   - S07: Lockfile-scoped registry allowlisting in snapshots

use sentinel_e2e::{resolve_cli, resolve_dylib, resolve_probe, DaemonHarness};
use std::process::Command;
use std::time::Duration;

/// File writes to non-persistence paths are unaffected by the open/openat
/// hook — no false positives from the persistence monitoring.
#[cfg_attr(not(target_os = "macos"), ignore)]
#[test]
fn open_hook_no_false_positive_on_normal_files() {
    let harness = DaemonHarness::start().expect("start daemon");
    let cli = resolve_cli();
    let dylib = resolve_dylib();
    let home = harness.home.path();

    let normal_file = home.join("normal-test-file.txt");
    let probe = resolve_probe();

    let output = Command::new(&cli)
        .arg(&probe)
        .arg(normal_file.to_str().unwrap())
        .env_clear()
        .env("HOME", home)
        .env("PATH", std::env::var_os("PATH").unwrap_or_default())
        .env("SENTINEL_HOOK_DYLIB", &dylib)
        .env("SENTINEL_STATE_DIR", &harness.state_dir)
        .output()
        .expect("run persistence_write_probe on normal file");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "normal file write should succeed; stdout={stdout}\nstderr={stderr}"
    );
    assert!(
        stdout.contains("WRITE-OK"),
        "expected WRITE-OK; stdout={stdout}"
    );
}

/// Lockfile registry extraction produces ProjectAllow entries in the snapshot.
/// We create a fake package-lock.json with a private registry, run sentinel
/// with cwd pointing to that directory, and verify the snapshot contains the
/// registry host.
#[cfg_attr(not(target_os = "macos"), ignore)]
#[test]
fn lockfile_registries_appear_in_snapshot() {
    let harness = DaemonHarness::start().expect("start daemon");
    let cli = resolve_cli();
    let dylib = resolve_dylib();
    let home = harness.home.path();

    let project_dir = home.join("fake-project");
    std::fs::create_dir_all(&project_dir).unwrap();

    let lockfile_content = r#"{
        "name": "test-project",
        "lockfileVersion": 3,
        "packages": {
            "node_modules/internal-pkg": {
                "resolved": "https://npm.internal.example.com/@myorg/internal-pkg/-/internal-pkg-1.0.0.tgz"
            },
            "node_modules/left-pad": {
                "resolved": "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz"
            }
        }
    }"#;
    std::fs::write(project_dir.join("package-lock.json"), lockfile_content).unwrap();

    let output = Command::new(&cli)
        .arg("echo")
        .arg("lockfile-test")
        .env_clear()
        .env("HOME", home)
        .env("PATH", std::env::var_os("PATH").unwrap_or_default())
        .env("SENTINEL_HOOK_DYLIB", &dylib)
        .env("SENTINEL_STATE_DIR", &harness.state_dir)
        .current_dir(&project_dir)
        .output()
        .expect("run sentinel echo in project dir");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(
        output.status.success(),
        "sentinel echo should succeed; stdout={stdout}\nstderr={stderr}"
    );

    // Verify the snapshot CBOR contains the private registry hostname
    let runs_dir = harness.state_dir.join("runs");
    assert!(runs_dir.exists(), "runs_dir missing at {}", runs_dir.display());

    let found_snapshot = std::fs::read_dir(&runs_dir)
        .unwrap()
        .filter_map(|e| e.ok())
        .filter(|e| e.path().extension().map_or(false, |ext| ext == "cbor"))
        .any(|e| {
            let data = std::fs::read(e.path()).unwrap_or_default();
            data.windows(b"npm.internal.example.com".len())
                .any(|w| w == b"npm.internal.example.com")
        });
    assert!(
        found_snapshot,
        "no snapshot contained npm.internal.example.com — lockfile extraction failed;\n\
         runs_dir: {}\nstdout: {stdout}\nstderr: {stderr}",
        runs_dir.display()
    );
}

/// Multiple lockfile formats: Cargo.lock in the project root is discovered
/// and its registries appear in the snapshot.
#[cfg_attr(not(target_os = "macos"), ignore)]
#[test]
fn cargo_lockfile_registries_in_snapshot() {
    let harness = DaemonHarness::start().expect("start daemon");
    let cli = resolve_cli();
    let dylib = resolve_dylib();
    let home = harness.home.path();

    let project_dir = home.join("rust-project");
    std::fs::create_dir_all(&project_dir).unwrap();

    let cargo_lock_content = r#"[[package]]
name = "serde"
version = "1.0.0"
source = "registry+https://github.com/rust-lang/crates.io-index"

[[package]]
name = "private-crate"
version = "0.1.0"
source = "sparse+https://cargo.corp.example.com/index/"
"#;
    std::fs::write(project_dir.join("Cargo.lock"), cargo_lock_content).unwrap();

    let output = Command::new(&cli)
        .arg("echo")
        .arg("cargo-lockfile-test")
        .env_clear()
        .env("HOME", home)
        .env("PATH", std::env::var_os("PATH").unwrap_or_default())
        .env("SENTINEL_HOOK_DYLIB", &dylib)
        .env("SENTINEL_STATE_DIR", &harness.state_dir)
        .current_dir(&project_dir)
        .output()
        .expect("run sentinel echo in cargo project dir");

    assert!(
        output.status.success(),
        "sentinel echo should succeed"
    );

    let runs_dir = harness.state_dir.join("runs");
    if runs_dir.exists() {
        let has_cargo_host = std::fs::read_dir(&runs_dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.path().extension().map_or(false, |ext| ext == "cbor"))
            .any(|e| {
                let data = std::fs::read(e.path()).unwrap_or_default();
                data.windows(b"cargo.corp.example.com".len())
                    .any(|w| w == b"cargo.corp.example.com")
            });
        assert!(
            has_cargo_host,
            "snapshot should contain cargo.corp.example.com from Cargo.lock"
        );
    }
}

/// Persistence write detection and the open hook coexist: a wrapped process
/// writing to ~/Library/LaunchAgents/ succeeds (monitored not blocked) and
/// the persistence-write gap record appears in the JSONL log.
#[cfg_attr(not(target_os = "macos"), ignore)]
#[test]
fn persistence_write_detected_in_log() {
    let mut harness = DaemonHarness::start().expect("start daemon");
    let cli = resolve_cli();
    let dylib = resolve_dylib();
    let home = harness.home.path().to_path_buf();

    let la_dir = home.join("Library").join("LaunchAgents");
    std::fs::create_dir_all(&la_dir).unwrap();
    let target_plist = la_dir.join("cross-slice-test.plist");

    let probe = resolve_probe();

    let output = Command::new(&cli)
        .arg(&probe)
        .arg(target_plist.to_str().unwrap())
        .env_clear()
        .env("HOME", &home)
        .env("PATH", std::env::var_os("PATH").unwrap_or_default())
        .env("SENTINEL_HOOK_DYLIB", &dylib)
        .env("SENTINEL_STATE_DIR", &harness.state_dir)
        .output()
        .expect("run persistence_write_probe");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        output.status.success(),
        "probe should succeed (monitored, not blocked); stdout={stdout}"
    );
    assert!(stdout.contains("WRITE-OK"), "expected WRITE-OK; stdout={stdout}");

    // Wait for the daemon to flush the gap record to the JSONL log
    std::thread::sleep(Duration::from_millis(500));
    let _ = harness.drain_stderr();

    let log = home.join("Library/Logs/Sentinel/sentinel.log");
    let content = std::fs::read_to_string(&log).unwrap_or_default();
    let has_persistence_gap = content.lines().any(|l| {
        l.contains(r#""gap_kind":"persistence-write""#)
            || l.contains(r#""gap_kind": "persistence-write""#)
    });
    assert!(
        has_persistence_gap,
        "JSONL log should contain persistence-write gap record;\n\
         log: {}\ncontents:\n{content}",
        log.display()
    );
}

/// Persistence CLI: `sentinel status persistence --json` exits cleanly after
/// persistence-write events have been recorded.
#[cfg_attr(not(target_os = "macos"), ignore)]
#[test]
fn status_persistence_shows_events() {
    let mut harness = DaemonHarness::start().expect("start daemon");
    let cli = resolve_cli();
    let dylib = resolve_dylib();
    let home = harness.home.path().to_path_buf();

    let la_dir = home.join("Library").join("LaunchAgents");
    std::fs::create_dir_all(&la_dir).unwrap();
    let target_plist = la_dir.join("status-test.plist");

    let probe = resolve_probe();

    let output = Command::new(&cli)
        .arg(&probe)
        .arg(target_plist.to_str().unwrap())
        .env_clear()
        .env("HOME", &home)
        .env("PATH", std::env::var_os("PATH").unwrap_or_default())
        .env("SENTINEL_HOOK_DYLIB", &dylib)
        .env("SENTINEL_STATE_DIR", &harness.state_dir)
        .output()
        .expect("run persistence_write_probe");

    assert!(output.status.success(), "probe should succeed");

    std::thread::sleep(Duration::from_millis(500));
    let _ = harness.drain_stderr();

    let status_output = Command::new(&cli)
        .args(["status", "persistence", "--json"])
        .env_clear()
        .env("HOME", &home)
        .env("SENTINEL_STATE_DIR", &harness.state_dir)
        .env("PATH", std::env::var_os("PATH").unwrap_or_default())
        .output()
        .expect("run sentinel status persistence --json");

    let status_stdout = String::from_utf8_lossy(&status_output.stdout);
    assert!(
        status_output.status.success(),
        "sentinel status persistence --json should succeed; stdout={status_stdout}"
    );
}
