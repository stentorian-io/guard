//! Phase 3 plan 03-16 (gap closure for UAT item #1) — Tier B real-launchctl
//! coverage. Performs an actual `launchctl bootstrap` and `launchctl bootout`
//! round-trip. Requires a live macOS user GUI session.
//!
//! Enable with:
//!   cargo test -p sentinel-e2e --features ci-launchd --test install_uninstall_launchd
//!
//! Default `cargo test` invocations skip this entire file silently (no
//! `#[ignore]` attribute — the cfg gate keeps the test name out of the
//! discovery output too, which is the cleaner pattern for opt-in features).

#![cfg(all(target_os = "macos", feature = "ci-launchd"))]

use std::io::Write as _;
use std::process::{Command, Stdio};
use std::time::Duration;

use sentinel_e2e::{cargo_target_dir, resolve_cli};

/// Launchctl IS invoked (env gate NOT set). Asserts the daemon ends up
/// registered in the user's launchd domain after install, and unregistered
/// after uninstall. We use `launchctl print gui/$(id -u)/com.sentinel.daemon`
/// (returns 0 if registered, non-zero if not).
#[test]
fn launchctl_bootstrap_and_bootout_round_trip() {
    let home = tempfile::tempdir().expect("home tempdir");
    let state_tmp = tempfile::Builder::new()
        .prefix(".se2e16ci")
        .tempdir_in("/tmp")
        .expect("state_dir tempdir");
    let state_dir = state_tmp.path().to_path_buf();

    let cli = resolve_cli();
    let daemon_bin = cargo_target_dir().join("sentineld");

    // SETUP DAEMON — no SENTINEL_SKIP_LAUNCHCTL. Real launchctl bootstrap fires.
    // Phase 07 plan 05 (D-09, D-10): `install --no-shell-integration` → `setup daemon`.
    let mut child = Command::new(&cli)
        .arg("setup").arg("daemon")
        .env_clear()
        .env("HOME", home.path())
        .env("PATH", std::env::var_os("PATH").unwrap_or_default())
        .env("SENTINEL_DAEMON_BINARY", &daemon_bin)
        .env("SENTINEL_STATE_DIR", &state_dir)
        .stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped())
        .spawn().expect("spawn sentinel setup daemon");
    if let Some(mut stdin) = child.stdin.take() {
        let _ = stdin.write_all(b"y\n");
    }
    let install_out = child.wait_with_output().expect("setup daemon wait");
    if !install_out.status.success() {
        // launchctl bootstrap commonly fails on CI runners without a GUI
        // session. Print stderr and skip rather than fail; the maintainer
        // running this with --features ci-launchd has signalled they expect
        // launchctl to work.
        panic!(
            "sentinel setup daemon failed; launchctl unavailable on this runner?\n\
             stdout: {}\nstderr: {}",
            String::from_utf8_lossy(&install_out.stdout),
            String::from_utf8_lossy(&install_out.stderr),
        );
    }

    // Allow launchd time to register.
    std::thread::sleep(Duration::from_millis(500));

    // Assert the daemon label is registered.
    let uid_out = Command::new("id").arg("-u").output().expect("id -u");
    let uid = String::from_utf8(uid_out.stdout).expect("uid utf8").trim().to_string();
    let print_out = Command::new("launchctl")
        .arg("print")
        .arg(format!("gui/{uid}/com.sentinel.daemon"))
        .output()
        .expect("launchctl print");
    assert!(print_out.status.success(),
        "expected launchctl to report com.sentinel.daemon registered; \
         stdout: {}\nstderr: {}",
        String::from_utf8_lossy(&print_out.stdout),
        String::from_utf8_lossy(&print_out.stderr));

    // SETUP --REMOVE -y — real launchctl bootout fires.
    // Phase 07 plan 05 (D-09, D-10): `uninstall --force` → `setup --remove -y`.
    let uninstall_out = Command::new(&cli)
        .arg("setup").arg("--remove").arg("-y")
        .env_clear()
        .env("HOME", home.path())
        .env("PATH", std::env::var_os("PATH").unwrap_or_default())
        .env("SENTINEL_STATE_DIR", &state_dir)
        .output().expect("setup --remove wait");
    assert!(uninstall_out.status.success(),
        "setup --remove failed: stderr={}", String::from_utf8_lossy(&uninstall_out.stderr));

    std::thread::sleep(Duration::from_millis(500));

    // Assert the label is no longer registered (print returns non-zero).
    let print_after = Command::new("launchctl")
        .arg("print")
        .arg(format!("gui/{uid}/com.sentinel.daemon"))
        .output()
        .expect("launchctl print after");
    assert!(!print_after.status.success(),
        "expected launchctl to report com.sentinel.daemon UNregistered after uninstall; \
         stdout: {}",
        String::from_utf8_lossy(&print_after.stdout));
}
