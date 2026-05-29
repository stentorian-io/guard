//! Privileged e2e coverage for the system installer and hardened install health.
//!
//! This test intentionally mutates system install locations and therefore runs
//! only when `STT_GUARD_E2E_PRIVILEGED_INSTALL=1` is set. The GitHub validation
//! workflow sets that env var on ephemeral macOS runners. Ordinary local
//! `cargo test` runs skip it to avoid touching a developer machine.

#[cfg(target_os = "macos")]
mod macos {
    use std::ffi::OsStr;
    use std::net::TcpListener;
    use std::path::Path;
    use std::path::PathBuf;
    use std::process::{Command, Output};
    use std::thread;
    use std::time::{Duration, Instant};

    use guard_e2e::{cargo_target_dir, resolve_cli};

    const ENABLE_ENV: &str = "STT_GUARD_E2E_PRIVILEGED_INSTALL";
    const BIN_DIR: &str = "/usr/local/libexec/stt-guard";
    const STATE_DIR: &str = "/Library/Application Support/Stentorian Guard";
    const LOG_DIR: &str = "/var/log/stt-guard";
    const PLIST_PATH: &str = "/Library/LaunchDaemons/io.stentorian.guard.daemon.plist";
    const PLIST_LABEL: &str = "io.stentorian.guard.daemon";

    struct Cleanup;

    impl Drop for Cleanup {
        fn drop(&mut self) {
            cleanup_system_install();
        }
    }

    #[test]
    fn privileged_init_and_health_fail_closed_on_corruption() {
        if std::env::var_os(ENABLE_ENV).as_deref() != Some(OsStr::new("1")) {
            eprintln!("SKIP: set {ENABLE_ENV}=1 to run privileged install e2e");
            return;
        }

        let cli = resolve_cli();
        let target_dir = cargo_target_dir();
        ensure_install_named_hook_dylib(&target_dir);
        assert_release_payload_present(&target_dir);

        cleanup_system_install();
        let _cleanup = Cleanup;

        assert_pre_install_refuses(&cli);
        if !install_system_or_skip(&cli) {
            return;
        }

        wait_for_status_ok(&cli);
        assert_wrapped_user_process_loads_system_snapshot_and_enforces_policy(&cli, &target_dir);
        assert_hook_mode_tampering_detected(&cli);
        assert_plist_tampering_detected(&cli);
        assert_watchdog_symlink_detected(&cli, &target_dir);
        assert_hook_override_ignored(&cli);
    }

    fn assert_pre_install_refuses(cli: &Path) {
        let before = run_cli(cli, ["status", "logs"]);
        assert!(
            !before.status.success(),
            "status logs should refuse before system install; stdout={} stderr={}",
            stdout(&before),
            stderr(&before)
        );
        assert_contains(
            &stderr(&before),
            "hardened install is missing, corrupted, or incorrectly set up",
        );
    }

    fn install_system_or_skip(cli: &Path) -> bool {
        let install = sudo([
            cli.as_os_str(),
            OsStr::new("install-system"),
            OsStr::new("--yes"),
        ]);
        if !install.status.success() && hardware_signing_unavailable(&stderr(&install)) {
            eprintln!(
                "SKIP: hosted runner cannot enroll Secure Enclave signing key; stdout={} stderr={}",
                stdout(&install),
                stderr(&install)
            );
            return false;
        }
        assert!(
            install.status.success(),
            "system install failed; stdout={} stderr={}",
            stdout(&install),
            stderr(&install)
        );

        true
    }

    fn assert_hook_mode_tampering_detected(cli: &Path) {
        sudo_ok([
            OsStr::new("chmod"),
            OsStr::new("666"),
            OsStr::new(&format!("{BIN_DIR}/stt-guard-hook.dylib")),
        ]);
        let bad_mode = run_cli(cli, ["status", "logs"]);
        assert_health_failure_contains(&bad_mode, "mode is 0666");
        sudo_ok([
            OsStr::new("chmod"),
            OsStr::new("644"),
            OsStr::new(&format!("{BIN_DIR}/stt-guard-hook.dylib")),
        ]);
        assert!(run_cli(cli, ["status", "logs"]).status.success());
    }

    fn assert_plist_tampering_detected(cli: &Path) {
        let backup = tempfile::NamedTempFile::new().expect("plist backup temp file");
        std::fs::copy(PLIST_PATH, backup.path()).expect("backup plist");
        sudo_ok([
            OsStr::new("sh"),
            OsStr::new("-c"),
            OsStr::new(&format!("printf '\n<!-- tampered -->\n' >> '{PLIST_PATH}'")),
        ]);
        let tampered_plist = run_cli(cli, ["status", "logs"]);
        assert_health_failure_contains(
            &tampered_plist,
            "content differs from expected LaunchDaemon definition",
        );
        sudo_ok([
            OsStr::new("cp"),
            backup.path().as_os_str(),
            OsStr::new(PLIST_PATH),
        ]);
        sudo_ok([
            OsStr::new("chown"),
            OsStr::new("root:wheel"),
            OsStr::new(PLIST_PATH),
        ]);
        sudo_ok([
            OsStr::new("chmod"),
            OsStr::new("644"),
            OsStr::new(PLIST_PATH),
        ]);
        assert!(run_cli(cli, ["status", "logs"]).status.success());
    }

    fn assert_watchdog_symlink_detected(cli: &Path, target_dir: &Path) {
        sudo_ok([
            OsStr::new("rm"),
            OsStr::new("-f"),
            OsStr::new(&format!("{BIN_DIR}/stt-guard-watchdog")),
        ]);
        sudo_ok([
            OsStr::new("ln"),
            OsStr::new("-s"),
            OsStr::new(&format!("{BIN_DIR}/stt-guard-daemon")),
            OsStr::new(&format!("{BIN_DIR}/stt-guard-watchdog")),
        ]);
        let symlinked_watchdog = run_cli(cli, ["status", "logs"]);
        assert_health_failure_contains(&symlinked_watchdog, "must not be a symlink");
        sudo_ok([
            OsStr::new("rm"),
            OsStr::new("-f"),
            OsStr::new(&format!("{BIN_DIR}/stt-guard-watchdog")),
        ]);
        sudo_ok([
            OsStr::new("cp"),
            target_dir.join("stt-guard-watchdog").as_os_str(),
            OsStr::new(&format!("{BIN_DIR}/stt-guard-watchdog")),
        ]);
        sudo_ok([
            OsStr::new("chown"),
            OsStr::new("root:wheel"),
            OsStr::new(&format!("{BIN_DIR}/stt-guard-watchdog")),
        ]);
        sudo_ok([
            OsStr::new("chmod"),
            OsStr::new("755"),
            OsStr::new(&format!("{BIN_DIR}/stt-guard-watchdog")),
        ]);
        assert!(run_cli(cli, ["status", "logs"]).status.success());
    }

    fn assert_hook_override_ignored(cli: &Path) {
        let fake_hook = tempfile::NamedTempFile::new().expect("fake hook");
        std::fs::write(fake_hook.path(), b"not a dylib").expect("write fake hook");
        let env_override = Command::new(cli)
            .arg("wrap")
            .arg(cli)
            .arg("--version")
            .current_dir("/tmp")
            .env_clear()
            .env("HOME", test_home())
            .env("PATH", std::env::var_os("PATH").unwrap_or_default())
            .env("STT_GUARD_HOOK_DYLIB", fake_hook.path())
            .output()
            .expect("run wrap with fake env hook");
        assert!(
            env_override.status.success(),
            "production hook lookup should ignore STT_GUARD_HOOK_DYLIB; stdout={} stderr={}",
            stdout(&env_override),
            stderr(&env_override)
        );
    }

    fn ensure_install_named_hook_dylib(target_dir: &Path) {
        let install_name = target_dir.join("stt-guard-hook.dylib");
        if install_name.exists() {
            return;
        }
        let cargo_name = target_dir.join("libguard_hook.dylib");
        assert!(
            cargo_name.is_file(),
            "Cargo hook dylib missing {}; run cargo build --workspace --release first",
            cargo_name.display()
        );
        std::fs::copy(&cargo_name, &install_name).unwrap_or_else(|err| {
            panic!(
                "copy {} -> {}: {err}",
                cargo_name.display(),
                install_name.display()
            )
        });
    }

    fn assert_wrapped_user_process_loads_system_snapshot_and_enforces_policy(
        cli: &Path,
        target_dir: &Path,
    ) {
        let probe = target_dir.join("zero_config_probe");
        assert!(
            probe.is_file(),
            "zero_config_probe missing {}; run cargo build --workspace --release first",
            probe.display()
        );

        let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback listener");
        let port = listener.local_addr().expect("listener addr").port();
        let addr_a = format!("127.0.0.1:{port}");
        spawn_accept_thread(listener);

        let baseline = Command::new(&probe)
            .args([&addr_a, &addr_a])
            .output()
            .expect("run zero_config_probe baseline");
        assert_eq!(
            baseline.status.code(),
            Some(3),
            "baseline probe must connect to loopback twice; stdout={} stderr={}",
            stdout(&baseline),
            stderr(&baseline)
        );

        let out = Command::new(cli)
            .arg("wrap")
            .arg(&probe)
            .arg(&addr_a)
            .arg("192.0.2.1:80")
            .current_dir(test_work_dir())
            .env_clear()
            .env("HOME", test_home())
            .env("PATH", std::env::var_os("PATH").unwrap_or_default())
            .output()
            .expect("run system stt-guard wrap with zero_config_probe");
        let exit_code = out.status.code().unwrap_or(-1);

        assert!(
            exit_code & 1 == 1,
            "system wrapped command did not allow loopback; exit={exit_code} stdout={} stderr={}",
            stdout(&out),
            stderr(&out)
        );
        assert!(
            exit_code & 2 == 0,
            "system wrapped command did not deny TEST-NET destination; exit={exit_code} stdout={} stderr={}",
            stdout(&out),
            stderr(&out)
        );
    }

    fn spawn_accept_thread(listener: TcpListener) {
        thread::spawn(move || {
            for stream in listener.incoming().flatten() {
                drop(stream);
            }
        });
    }

    fn test_work_dir() -> PathBuf {
        let dir = std::env::temp_dir().join("stt-guard-hardened-install-e2e-work");
        std::fs::create_dir_all(&dir).expect("create test work dir");
        dir
    }

    fn hardware_signing_unavailable(stderr: &str) -> bool {
        stderr.contains("create Secure Enclave signing key failed")
            || stderr.contains("hardware-backed signing key unavailable")
            || stderr.contains("failed to generate asymmetric keypair")
    }

    fn assert_release_payload_present(target_dir: &Path) {
        for file in [
            "stt-guard",
            "stt-guard-daemon",
            "stt-guard-watchdog",
            "stt-guard-hook.dylib",
        ] {
            assert!(
                target_dir.join(file).is_file(),
                "release payload missing {}; run cargo build --workspace --release first",
                target_dir.join(file).display()
            );
        }
    }

    fn run_cli<const N: usize>(cli: &Path, args: [&str; N]) -> Output {
        Command::new(cli)
            .args(args)
            .env_clear()
            .env("HOME", test_home())
            .env("PATH", std::env::var_os("PATH").unwrap_or_default())
            .output()
            .expect("run stt-guard")
    }

    fn test_home() -> std::ffi::OsString {
        std::env::var_os("HOME").unwrap_or_else(|| std::ffi::OsString::from("/tmp"))
    }

    fn wait_for_status_ok(cli: &Path) {
        let deadline = Instant::now() + Duration::from_secs(15);
        loop {
            let out = run_cli(cli, ["status"]);
            if out.status.success() {
                return;
            }
            assert!(
                Instant::now() < deadline,
                "status did not become healthy after system install; stdout={} stderr={}",
                stdout(&out),
                stderr(&out)
            );
            std::thread::sleep(Duration::from_millis(500));
        }
    }

    fn assert_health_failure_contains(out: &Output, needle: &str) {
        assert!(
            !out.status.success(),
            "expected health check failure containing {needle:?}; stdout={} stderr={}",
            stdout(out),
            stderr(out)
        );
        assert_contains(&stderr(out), needle);
    }

    fn assert_contains(haystack: &str, needle: &str) {
        assert!(
            haystack.contains(needle),
            "expected output to contain {needle:?}; got {haystack:?}"
        );
    }

    fn sudo<const N: usize>(args: [&OsStr; N]) -> Output {
        Command::new("sudo")
            .arg("-n")
            .args(args)
            .env_clear()
            .env("HOME", test_home())
            .env("PATH", std::env::var_os("PATH").unwrap_or_default())
            .output()
            .expect("run sudo")
    }

    fn sudo_ok<const N: usize>(args: [&OsStr; N]) {
        let out = sudo(args);
        assert!(
            out.status.success(),
            "sudo command failed; stdout={} stderr={}",
            stdout(&out),
            stderr(&out)
        );
    }

    fn cleanup_system_install() {
        let _ = sudo([
            OsStr::new("launchctl"),
            OsStr::new("bootout"),
            OsStr::new(&format!("system/{PLIST_LABEL}")),
        ]);
        let _ = sudo([OsStr::new("rm"), OsStr::new("-f"), OsStr::new(PLIST_PATH)]);
        let _ = sudo([OsStr::new("rm"), OsStr::new("-rf"), OsStr::new(BIN_DIR)]);
        let _ = sudo([OsStr::new("rm"), OsStr::new("-rf"), OsStr::new(STATE_DIR)]);
        let _ = sudo([OsStr::new("rm"), OsStr::new("-rf"), OsStr::new(LOG_DIR)]);
    }

    fn stdout(out: &Output) -> String {
        String::from_utf8_lossy(&out.stdout).into_owned()
    }

    fn stderr(out: &Output) -> String {
        String::from_utf8_lossy(&out.stderr).into_owned()
    }
}

#[cfg(not(target_os = "macos"))]
#[test]
fn privileged_init_and_health_fail_closed_on_corruption() {
    eprintln!("SKIP: hardened install e2e only runs on macOS");
}
