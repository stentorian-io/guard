//! Pedantic hardened-install health checks.
//!
//! The install gate is intentionally stricter than "does the daemon binary
//! exist?". A partial or tampered layout is treated as not installed because a
//! false sense of protection is worse than a loud refusal.

use std::fs::{self, FileType, Metadata};
use std::os::unix::fs::{FileTypeExt, MetadataExt};
use std::path::Path;
use std::process::Command;

use guard_core::paths;

const ROOT_UID: u32 = 0;
const ROOT_GROUP_GID: u32 = 0;

#[cfg(target_os = "macos")]
const SERVICE_USER_HOME: &str = "/var/empty";
#[cfg(target_os = "linux")]
const SERVICE_USER_HOME: &str = paths::SYSTEM_STATE_DIR;

#[cfg(target_os = "macos")]
const SERVICE_USER_SHELL: &str = "/usr/bin/false";
#[cfg(target_os = "linux")]
const SERVICE_USER_SHELL: &str = "/usr/sbin/nologin";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstallHealth {
    problems: Vec<String>,
}

impl InstallHealth {
    #[must_use]
    pub fn healthy() -> Self {
        Self {
            problems: Vec::new(),
        }
    }

    #[must_use]
    pub fn is_healthy(&self) -> bool {
        self.problems.is_empty()
    }

    #[must_use]
    pub fn problems(&self) -> &[String] {
        &self.problems
    }

    fn push(&mut self, problem: impl Into<String>) {
        self.problems.push(problem.into());
    }

    #[must_use]
    pub fn error_message(&self) -> String {
        if self.is_healthy() {
            return "Stentorian Guard install is healthy".to_string();
        }
        let mut msg = String::from(
            "Stentorian Guard hardened install is missing, corrupted, or incorrectly set up.\n\
             Refusing to continue because this can silently weaken protection.\n\
             Run the installer, or run stt-guard update from an existing install.\n\nProblems:",
        );
        for problem in &self.problems {
            msg.push_str("\n  - ");
            msg.push_str(problem);
        }
        msg
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ExpectedKind {
    Directory,
    RegularFile,
}

/// Check the full hardened install layout.
#[must_use]
pub fn check_installation() -> InstallHealth {
    let mut health = InstallHealth::healthy();

    let service_ids = check_service_identity(&mut health);

    check_path(
        &mut health,
        Path::new(paths::SYSTEM_BIN_DIR),
        ExpectedKind::Directory,
        ROOT_UID,
        ROOT_GROUP_GID,
        0o755,
    );
    for binary in paths::INSTALLED_BINARIES {
        check_path(
            &mut health,
            &Path::new(paths::SYSTEM_BIN_DIR).join(binary),
            ExpectedKind::RegularFile,
            ROOT_UID,
            ROOT_GROUP_GID,
            0o755,
        );
    }
    check_path(
        &mut health,
        Path::new(paths::SYSTEM_HOOK_PATH),
        ExpectedKind::RegularFile,
        ROOT_UID,
        ROOT_GROUP_GID,
        0o644,
    );
    check_path(
        &mut health,
        &paths::trusted_rule_signers_path(),
        ExpectedKind::RegularFile,
        ROOT_UID,
        ROOT_GROUP_GID,
        0o644,
    );

    if let Some((uid, gid)) = service_ids {
        check_path(
            &mut health,
            Path::new(paths::SYSTEM_STATE_DIR),
            ExpectedKind::Directory,
            uid,
            gid,
            0o711,
        );
        check_path(
            &mut health,
            Path::new(paths::SYSTEM_LOG_DIR),
            ExpectedKind::Directory,
            uid,
            gid,
            0o711,
        );
    } else {
        check_path_exists_only(&mut health, Path::new(paths::SYSTEM_STATE_DIR));
        check_path_exists_only(&mut health, Path::new(paths::SYSTEM_LOG_DIR));
    }

    #[cfg(target_os = "macos")]
    {
        check_path(
            &mut health,
            Path::new(paths::PLIST_PATH),
            ExpectedKind::RegularFile,
            ROOT_UID,
            ROOT_GROUP_GID,
            0o644,
        );
        check_plist_content(&mut health);
    }

    #[cfg(target_os = "linux")]
    check_systemd_unit(&mut health);

    health
}

fn check_service_identity(health: &mut InstallHealth) -> Option<(u32, u32)> {
    let uid = numeric_id(
        "id",
        &["-u", paths::SERVICE_USER],
        "service user uid",
        health,
    )?;
    let gid = numeric_id(
        "id",
        &["-g", paths::SERVICE_USER],
        "service user gid",
        health,
    )?;

    check_service_user_record(health, uid, gid);

    Some((uid, gid))
}

#[cfg(target_os = "macos")]
fn check_service_user_record(health: &mut InstallHealth, uid: u32, gid: u32) {
    let output = Command::new("dscacheutil")
        .args(["-q", "user", "-a", "name", paths::SERVICE_USER])
        .output();
    let output = match output {
        Ok(output) => output,
        Err(err) => {
            health.push(format!(
                "service user record invalid: cannot execute dscacheutil: {err}"
            ));
            return;
        }
    };
    if !output.status.success() {
        health.push(format!(
            "service user record invalid: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
        return;
    }

    let record = String::from_utf8_lossy(&output.stdout);
    require_cache_field(health, &record, "uid", &uid.to_string());
    require_cache_field(health, &record, "gid", &gid.to_string());
    require_cache_field(health, &record, "dir", SERVICE_USER_HOME);
    require_cache_field(health, &record, "shell", SERVICE_USER_SHELL);
    require_cache_field(health, &record, "gecos", paths::SERVICE_USER_REALNAME);
}

#[cfg(target_os = "linux")]
fn check_service_user_record(health: &mut InstallHealth, uid: u32, gid: u32) {
    let output = Command::new("getent")
        .args(["passwd", paths::SERVICE_USER])
        .output();
    let output = match output {
        Ok(output) => output,
        Err(err) => {
            health.push(format!(
                "service user record invalid: cannot execute getent: {err}"
            ));
            return;
        }
    };
    if !output.status.success() {
        health.push(format!(
            "service user record invalid: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
        return;
    }

    let record = String::from_utf8_lossy(&output.stdout);
    check_getent_passwd_record(health, &record, uid, gid);
}

#[cfg(target_os = "linux")]
fn check_getent_passwd_record(health: &mut InstallHealth, record: &str, uid: u32, gid: u32) {
    let Some(line) = record.lines().next() else {
        health.push("service user record invalid: getent returned no passwd row");
        return;
    };
    let fields: Vec<&str> = line.split(':').collect();
    if fields.len() != 7 {
        health.push("service user record invalid: malformed passwd row");
        return;
    }

    require_passwd_field(health, "name", fields[0], paths::SERVICE_USER);
    require_passwd_field(health, "uid", fields[2], &uid.to_string());
    require_passwd_field(health, "gid", fields[3], &gid.to_string());
    require_passwd_field(health, "gecos", fields[4], paths::SERVICE_USER_REALNAME);
    require_passwd_field(health, "dir", fields[5], SERVICE_USER_HOME);
    require_passwd_field(health, "shell", fields[6], SERVICE_USER_SHELL);
}

#[cfg(target_os = "linux")]
fn require_passwd_field(health: &mut InstallHealth, key: &str, actual: &str, expected: &str) {
    if actual != expected {
        health.push(format!(
            "service user {key} does not match expected {expected:?}"
        ));
    }
}

fn numeric_id(
    program: &str,
    args: &[&str],
    description: &str,
    health: &mut InstallHealth,
) -> Option<u32> {
    let output = Command::new(program).args(args).output();
    let output = match output {
        Ok(output) => output,
        Err(err) => {
            health.push(format!("{description}: cannot execute {program}: {err}"));
            return None;
        }
    };
    if !output.status.success() {
        health.push(format!(
            "{description}: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
        return None;
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    match stdout.trim().parse::<u32>() {
        Ok(id) => Some(id),
        Err(err) => {
            health.push(format!(
                "{description}: malformed id {:?}: {err}",
                stdout.trim()
            ));
            None
        }
    }
}

#[cfg(target_os = "macos")]
fn require_cache_field(health: &mut InstallHealth, record: &str, key: &str, value: &str) {
    if !cache_field_values(record, key)
        .iter()
        .any(|actual| actual == value)
    {
        health.push(format!(
            "service user {key} does not match expected {value:?}"
        ));
    }
}

#[cfg(target_os = "macos")]
fn cache_field_values(record: &str, key: &str) -> Vec<String> {
    record
        .lines()
        .filter_map(|line| line.strip_prefix(&format!("{key}:")))
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(ToOwned::to_owned)
        .collect()
}

fn check_path_exists_only(health: &mut InstallHealth, path: &Path) {
    if let Err(err) = fs::symlink_metadata(path) {
        health.push(format!("{} missing or unreadable: {err}", path.display()));
    }
}

fn check_path(
    health: &mut InstallHealth,
    path: &Path,
    expected_kind: ExpectedKind,
    expected_owner_uid: u32,
    expected_group_gid: u32,
    expected_mode: u32,
) {
    match fs::symlink_metadata(path) {
        Ok(metadata) => check_metadata(
            health,
            path,
            &metadata,
            expected_kind,
            expected_owner_uid,
            expected_group_gid,
            expected_mode,
        ),
        Err(err) => health.push(format!("{} missing or unreadable: {err}", path.display())),
    }
}

fn check_metadata(
    health: &mut InstallHealth,
    path: &Path,
    metadata: &Metadata,
    expected_kind: ExpectedKind,
    expected_owner_uid: u32,
    expected_group_gid: u32,
    expected_mode: u32,
) {
    let file_type = metadata.file_type();
    if file_type.is_symlink() {
        health.push(format!("{} must not be a symlink", path.display()));
        return;
    }
    if is_special_file_type(file_type) {
        health.push(format!("{} must not be a special file", path.display()));
        return;
    }
    match expected_kind {
        ExpectedKind::Directory if !file_type.is_dir() => {
            health.push(format!("{} must be a directory", path.display()));
        }
        ExpectedKind::RegularFile if !file_type.is_file() => {
            health.push(format!("{} must be a regular file", path.display()));
        }
        _ => {}
    }

    if metadata.uid() != expected_owner_uid {
        health.push(format!(
            "{} owner uid is {}, expected {}",
            path.display(),
            metadata.uid(),
            expected_owner_uid
        ));
    }
    if metadata.gid() != expected_group_gid {
        health.push(format!(
            "{} group gid is {}, expected {}",
            path.display(),
            metadata.gid(),
            expected_group_gid
        ));
    }
    let mode = metadata.mode() & 0o7777;
    if mode != expected_mode {
        health.push(format!(
            "{} mode is {:04o}, expected {:04o}",
            path.display(),
            mode,
            expected_mode
        ));
    }
}

fn is_special_file_type(file_type: FileType) -> bool {
    file_type.is_block_device()
        || file_type.is_char_device()
        || file_type.is_fifo()
        || file_type.is_socket()
}

#[cfg(target_os = "macos")]
#[must_use]
pub fn expected_launchdaemon_plist() -> String {
    let environment_variables = launchdaemon_environment_variables_plist();

    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>{}</string>
    <key>ProgramArguments</key>
    <array>
        <string>{}/stt-guard-daemon</string>
        <string>serve</string>
        <string>--state-dir</string>
        <string>{}</string>
    </array>
    <key>UserName</key>
    <string>{}</string>
{}    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardOutPath</key>
    <string>{}/daemon.out.log</string>
    <key>StandardErrorPath</key>
    <string>{}/daemon.err.log</string>
</dict>
</plist>
"#,
        paths::PLIST_LABEL,
        paths::SYSTEM_BIN_DIR,
        paths::SYSTEM_STATE_DIR,
        paths::SERVICE_USER,
        environment_variables,
        paths::SYSTEM_LOG_DIR,
        paths::SYSTEM_LOG_DIR,
    )
}

#[cfg(all(target_os = "macos", feature = "test-signer"))]
fn launchdaemon_environment_variables_plist() -> &'static str {
    concat!(
        "    <key>EnvironmentVariables</key>\n",
        "    <dict>\n",
        "        <key>STT_GUARD_ALLOW_TEST_SIGNER</key>\n",
        "        <string>1</string>\n",
        "    </dict>\n",
    )
}

#[cfg(all(target_os = "macos", not(feature = "test-signer")))]
fn launchdaemon_environment_variables_plist() -> &'static str {
    ""
}

#[cfg(target_os = "macos")]
fn check_plist_content(health: &mut InstallHealth) {
    match fs::read_to_string(paths::PLIST_PATH) {
        Ok(content) if content == expected_launchdaemon_plist() => {}
        Ok(_) => health.push(format!(
            "{} content differs from expected LaunchDaemon definition",
            paths::PLIST_PATH
        )),
        Err(err) => health.push(format!("{} unreadable: {err}", paths::PLIST_PATH)),
    }
}

#[cfg(target_os = "linux")]
pub fn expected_systemd_daemon_unit() -> String {
    format!(
        r#"[Unit]
Description=Stentorian Guard daemon
Documentation=https://github.com/stentorian-io/guard
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User={}
Group={}
ExecStart={}/{} serve --state-dir {}
Restart=always
RestartSec=1s
NoNewPrivileges=true
PrivateTmp=true
ProtectHome=true
ProtectSystem=strict
ReadWritePaths={} {}
RestrictSUIDSGID=true
LockPersonality=true
CapabilityBoundingSet=
SystemCallArchitectures=native

[Install]
WantedBy=multi-user.target
"#,
        paths::SERVICE_USER,
        paths::SERVICE_USER,
        paths::SYSTEM_BIN_DIR,
        paths::DAEMON_BIN,
        paths::SYSTEM_STATE_DIR,
        paths::SYSTEM_STATE_DIR,
        paths::SYSTEM_LOG_DIR,
    )
}

#[cfg(target_os = "linux")]
fn check_systemd_unit(health: &mut InstallHealth) {
    check_path(
        health,
        Path::new(paths::SYSTEMD_DAEMON_UNIT_PATH),
        ExpectedKind::RegularFile,
        ROOT_UID,
        ROOT_GROUP_GID,
        0o644,
    );

    match fs::read_to_string(paths::SYSTEMD_DAEMON_UNIT_PATH) {
        Ok(content) if content == expected_systemd_daemon_unit() => {}
        Ok(_) => health.push(format!(
            "{} content differs from expected systemd unit definition",
            paths::SYSTEMD_DAEMON_UNIT_PATH
        )),
        Err(err) => health.push(format!(
            "{} unreadable: {err}",
            paths::SYSTEMD_DAEMON_UNIT_PATH
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn error_message_lists_all_problems() {
        let health = InstallHealth {
            problems: vec!["first".into(), "second".into()],
        };
        let msg = health.error_message();
        assert!(msg.contains("Run the installer"));
        assert!(msg.contains("first"));
        assert!(msg.contains("second"));
    }

    #[test]
    fn check_metadata_accepts_exact_regular_file_metadata() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("file");
        fs::write(&path, b"ok").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        let metadata = fs::symlink_metadata(&path).unwrap();
        let mut health = InstallHealth::healthy();
        check_metadata(
            &mut health,
            &path,
            &metadata,
            ExpectedKind::RegularFile,
            metadata.uid(),
            metadata.gid(),
            0o644,
        );
        assert!(health.is_healthy(), "{:?}", health.problems());
    }

    #[test]
    fn check_metadata_flags_world_writable_modes() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("file");
        fs::write(&path, b"bad").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o666)).unwrap();
        let metadata = fs::symlink_metadata(&path).unwrap();
        let mut health = InstallHealth::healthy();
        check_metadata(
            &mut health,
            &path,
            &metadata,
            ExpectedKind::RegularFile,
            metadata.uid(),
            metadata.gid(),
            0o644,
        );
        assert!(health.problems().iter().any(|p| p.contains("mode is 0666")));
    }

    #[test]
    #[cfg(unix)]
    fn check_metadata_rejects_symlink() {
        let tmp = tempfile::tempdir().unwrap();
        let target = tmp.path().join("target");
        let link = tmp.path().join("link");
        fs::write(&target, b"target").unwrap();
        std::os::unix::fs::symlink(&target, &link).unwrap();
        let metadata = fs::symlink_metadata(&link).unwrap();
        let mut health = InstallHealth::healthy();
        check_metadata(
            &mut health,
            &link,
            &metadata,
            ExpectedKind::RegularFile,
            metadata.uid(),
            metadata.gid(),
            0o644,
        );
        assert!(
            health
                .problems()
                .iter()
                .any(|p| p.contains("must not be a symlink"))
        );
    }

    #[test]
    #[cfg(target_os = "macos")]
    fn expected_plist_contains_hardened_paths() {
        let plist = expected_launchdaemon_plist();
        assert!(plist.contains(paths::PLIST_LABEL));
        assert!(plist.contains(paths::SYSTEM_BIN_DIR));
        assert!(plist.contains(paths::SYSTEM_STATE_DIR));
        assert!(plist.contains(paths::SERVICE_USER));
    }

    #[test]
    #[cfg(all(target_os = "macos", feature = "test-signer"))]
    fn expected_plist_allows_test_signer_only_in_test_builds() {
        let plist = expected_launchdaemon_plist();

        assert!(plist.contains("STT_GUARD_ALLOW_TEST_SIGNER"));
        assert!(plist.contains("<string>1</string>"));
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn expected_systemd_unit_contains_hardened_paths() {
        let unit = expected_systemd_daemon_unit();

        assert!(unit.contains(paths::DAEMON_BIN));
        assert!(unit.contains(paths::SYSTEM_BIN_DIR));
        assert!(unit.contains(paths::SYSTEM_STATE_DIR));
        assert!(unit.contains(paths::SYSTEM_LOG_DIR));
        assert!(unit.contains(paths::SERVICE_USER));
        assert!(unit.contains("NoNewPrivileges=true"));
        assert!(unit.contains("ProtectSystem=strict"));
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn getent_passwd_record_requires_locked_service_identity() {
        let record = format!(
            "{}:x:427:427:{}:{}:{}\n",
            paths::SERVICE_USER,
            paths::SERVICE_USER_REALNAME,
            SERVICE_USER_HOME,
            SERVICE_USER_SHELL
        );
        let mut health = InstallHealth::healthy();

        check_getent_passwd_record(&mut health, &record, 427, 427);

        assert!(health.is_healthy(), "{:?}", health.problems());
    }
}
