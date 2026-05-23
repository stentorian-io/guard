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
const WHEEL_GID: u32 = 0;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstallHealth {
    problems: Vec<String>,
}

impl InstallHealth {
    pub fn healthy() -> Self {
        Self {
            problems: Vec::new(),
        }
    }

    pub fn is_healthy(&self) -> bool {
        self.problems.is_empty()
    }

    pub fn problems(&self) -> &[String] {
        &self.problems
    }

    fn push(&mut self, problem: impl Into<String>) {
        self.problems.push(problem.into());
    }

    pub fn error_message(&self) -> String {
        if self.is_healthy() {
            return "Stentorian Guard install is healthy".to_string();
        }
        let mut msg = String::from(
            "Stentorian Guard hardened install is missing, corrupted, or incorrectly set up.\n\
             Refusing to continue because this can silently weaken protection.\n\
             Run: sudo stt-guard init\n\nProblems:",
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
pub fn check_installation() -> InstallHealth {
    let mut health = InstallHealth::healthy();

    let service_ids = check_service_identity(&mut health);

    check_path(
        &mut health,
        Path::new(paths::SYSTEM_BIN_DIR),
        ExpectedKind::Directory,
        ROOT_UID,
        WHEEL_GID,
        0o755,
    );
    for binary in paths::INSTALLED_BINARIES {
        check_path(
            &mut health,
            &Path::new(paths::SYSTEM_BIN_DIR).join(binary),
            ExpectedKind::RegularFile,
            ROOT_UID,
            WHEEL_GID,
            0o755,
        );
    }
    check_path(
        &mut health,
        Path::new(paths::SYSTEM_HOOK_PATH),
        ExpectedKind::RegularFile,
        ROOT_UID,
        WHEEL_GID,
        0o644,
    );

    if let Some((uid, gid)) = service_ids {
        check_path(
            &mut health,
            Path::new(paths::SYSTEM_STATE_DIR),
            ExpectedKind::Directory,
            uid,
            gid,
            0o700,
        );
        check_path(
            &mut health,
            Path::new(paths::SYSTEM_LOG_DIR),
            ExpectedKind::Directory,
            uid,
            gid,
            0o700,
        );
    } else {
        check_path_exists_only(&mut health, Path::new(paths::SYSTEM_STATE_DIR));
        check_path_exists_only(&mut health, Path::new(paths::SYSTEM_LOG_DIR));
    }

    check_path(
        &mut health,
        Path::new(paths::PLIST_PATH),
        ExpectedKind::RegularFile,
        ROOT_UID,
        WHEEL_GID,
        0o644,
    );
    check_plist_content(&mut health);

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

    let user_record = dscl_read(
        &format!("/Users/{}", paths::SERVICE_USER),
        &[
            "UserShell",
            "NFSHomeDirectory",
            "RealName",
            "PrimaryGroupID",
        ],
    );
    match user_record {
        Ok(record) => {
            require_record_contains(health, &record, "UserShell", "/usr/bin/false");
            require_record_contains(health, &record, "NFSHomeDirectory", "/var/empty");
            require_record_contains(health, &record, "RealName", paths::SERVICE_USER_REALNAME);
            require_record_contains(health, &record, "PrimaryGroupID", &gid.to_string());
        }
        Err(err) => health.push(format!("service user record invalid: {err}")),
    }

    if let Err(err) = dscl_read(
        &format!("/Groups/{}", paths::SERVICE_USER),
        &["PrimaryGroupID"],
    ) {
        health.push(format!("service group record invalid: {err}"));
    }

    Some((uid, gid))
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

fn dscl_read(record: &str, attrs: &[&str]) -> Result<String, String> {
    let output = Command::new("dscl")
        .arg(".")
        .arg("-read")
        .arg(record)
        .args(attrs)
        .output()
        .map_err(|e| format!("cannot execute dscl: {e}"))?;
    if !output.status.success() {
        return Err(String::from_utf8_lossy(&output.stderr).trim().to_string());
    }
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

fn require_record_contains(health: &mut InstallHealth, record: &str, key: &str, value: &str) {
    if !record
        .lines()
        .any(|line| line.starts_with(key) && line.contains(value))
    {
        health.push(format!(
            "service user {key} does not match expected {value:?}"
        ));
    }
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
    expected_uid: u32,
    expected_gid: u32,
    expected_mode: u32,
) {
    match fs::symlink_metadata(path) {
        Ok(metadata) => check_metadata(
            health,
            path,
            &metadata,
            expected_kind,
            expected_uid,
            expected_gid,
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
    expected_uid: u32,
    expected_gid: u32,
    expected_mode: u32,
) {
    let file_type = metadata.file_type();
    if file_type.is_symlink() {
        health.push(format!("{} must not be a symlink", path.display()));
        return;
    }
    if is_special_file_type(&file_type) {
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

    if metadata.uid() != expected_uid {
        health.push(format!(
            "{} owner uid is {}, expected {}",
            path.display(),
            metadata.uid(),
            expected_uid
        ));
    }
    if metadata.gid() != expected_gid {
        health.push(format!(
            "{} group gid is {}, expected {}",
            path.display(),
            metadata.gid(),
            expected_gid
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

fn is_special_file_type(file_type: &FileType) -> bool {
    file_type.is_block_device()
        || file_type.is_char_device()
        || file_type.is_fifo()
        || file_type.is_socket()
}

pub fn expected_launchdaemon_plist() -> String {
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
    <key>GroupName</key>
    <string>{}</string>
    <key>RunAtLoad</key>
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
        paths::SERVICE_USER,
        paths::SYSTEM_LOG_DIR,
        paths::SYSTEM_LOG_DIR,
    )
}

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
        assert!(msg.contains("sudo stt-guard init"));
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
    fn expected_plist_contains_hardened_paths() {
        let plist = expected_launchdaemon_plist();
        assert!(plist.contains(paths::PLIST_LABEL));
        assert!(plist.contains(paths::SYSTEM_BIN_DIR));
        assert!(plist.contains(paths::SYSTEM_STATE_DIR));
        assert!(plist.contains(paths::SERVICE_USER));
    }
}
