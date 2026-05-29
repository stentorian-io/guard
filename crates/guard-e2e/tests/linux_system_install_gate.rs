//! Linux production install gate coverage.
//!
//! The Linux development path may auto-start a sibling daemon for user-state
//! directories, but the production system state directory must fail through the
//! hardened install health gate until the full systemd install exists.

#[cfg(target_os = "linux")]
mod linux {
    use std::path::Path;
    use std::process::Command;

    use guard_core::paths;
    use guard_e2e::resolve_cli;

    struct CreatedSystemStateDir {
        path: &'static Path,
        should_remove: bool,
    }

    impl Drop for CreatedSystemStateDir {
        fn drop(&mut self) {
            if self.should_remove {
                let _ = std::fs::remove_dir_all(self.path);
            }
        }
    }

    #[test]
    fn system_state_dir_requires_hardened_install_instead_of_development_daemon() {
        let system_state_dir = Path::new(paths::SYSTEM_STATE_DIR);
        let system_state_preexisting = system_state_dir.exists();
        if system_state_preexisting {
            eprintln!(
                "SKIP: {} already exists; refusing to disturb a host system install",
                system_state_dir.display()
            );
            return;
        }

        match std::fs::create_dir_all(system_state_dir) {
            Ok(()) => {}
            Err(err) if err.kind() == std::io::ErrorKind::PermissionDenied => {
                eprintln!(
                    "SKIP: cannot create {} without privileges: {err}",
                    system_state_dir.display()
                );
                return;
            }
            Err(err) => panic!("create {}: {err}", system_state_dir.display()),
        }
        let _cleanup = CreatedSystemStateDir {
            path: system_state_dir,
            should_remove: true,
        };

        let home = tempfile::tempdir().expect("temp home");
        let cli = resolve_cli();
        let output = Command::new(&cli)
            .arg("status")
            .env_clear()
            .env("HOME", home.path())
            .env("PATH", std::env::var_os("PATH").unwrap_or_default())
            .output()
            .expect("stt-guard status");

        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            !output.status.success(),
            "status should fail closed when Linux system state exists without a \
             hardened install; status={:?}\nstdout={stdout}\nstderr={stderr}",
            output.status
        );
        assert!(
            stderr.contains("hardened install is missing, corrupted, or incorrectly set up"),
            "status should fail through install health; stderr={stderr}"
        );
        assert!(
            stderr.contains(paths::SYSTEMD_DAEMON_UNIT_PATH),
            "install health should report the missing Linux systemd unit; stderr={stderr}"
        );
        assert!(
            !stderr.contains("Linux development daemon"),
            "system state must not use Linux development daemon fallback; stderr={stderr}"
        );
    }
}
