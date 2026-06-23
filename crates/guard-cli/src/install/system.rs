//! Hardened system-level installation.
//!
//! Creates the `_stt_guard` service user, deploys root-owned binaries to
//! `/usr/local/libexec/stt-guard/`, creates state and log directories owned
//! by `_stt_guard`, installs a `LaunchDaemon`, and starts it.

#[cfg(not(target_os = "linux"))]
use std::io::Write;
#[cfg(not(target_os = "linux"))]
use std::os::unix::fs::MetadataExt;
#[cfg(not(target_os = "linux"))]
use std::os::unix::fs::OpenOptionsExt;
#[cfg(not(target_os = "linux"))]
use std::os::unix::fs::PermissionsExt;
#[cfg(target_os = "linux")]
use std::path::PathBuf;
#[cfg(not(target_os = "linux"))]
use std::path::{Path, PathBuf};
#[cfg(not(target_os = "linux"))]
use std::process::Command;

use crate::CliError;
#[cfg(not(target_os = "linux"))]
use crate::hardware_signing::HardwareSignerEnrollment;

use guard_core::paths;

#[cfg(not(target_os = "linux"))]
const SERVICE_USER: &str = paths::SERVICE_USER;
#[cfg(not(target_os = "linux"))]
const SERVICE_USER_REALNAME: &str = paths::SERVICE_USER_REALNAME;

#[cfg(not(target_os = "linux"))]
const BIN_DIR: &str = paths::SYSTEM_BIN_DIR;
const STATE_DIR: &str = paths::SYSTEM_STATE_DIR;
#[cfg(not(target_os = "linux"))]
const LOG_DIR: &str = paths::SYSTEM_LOG_DIR;
#[cfg(not(target_os = "linux"))]
const PLIST_LABEL: &str = paths::PLIST_LABEL;
#[cfg(not(target_os = "linux"))]
const PLIST_PATH: &str = paths::PLIST_PATH;

#[cfg(not(target_os = "linux"))]
const BINARIES: &[&str] = paths::INSTALLED_BINARIES;
#[cfg(not(target_os = "linux"))]
const DYLIB: &str = paths::HOOK_DYLIB;
#[cfg(target_os = "macos")]
const CARGO_HOOK_DYLIB: &str = "libguard_hook.dylib";
#[cfg(all(not(target_os = "macos"), not(target_os = "linux")))]
const CARGO_HOOK_DYLIB: &str = paths::HOOK_DYLIB;
#[cfg(all(not(target_os = "linux"), feature = "test-signer"))]
const INSTALL_FAIL_STEP_ENV: &str = "STT_GUARD_INSTALL_FAIL_STEP";
#[cfg(all(target_os = "macos", not(feature = "test-signer")))]
const INSTALL_KEYCHAIN_ENROLLMENT_ENV: &str = "STT_GUARD_INSTALL_KEYCHAIN_ENROLLMENT";

/// Check whether the hardened installation is present and internally coherent.
#[must_use]
pub fn is_installed() -> bool {
    install_health().is_healthy()
}

/// Return the full hardened-install health result.
#[must_use]
pub fn install_health() -> crate::install::health::InstallHealth {
    crate::install::health::check_installation()
}

/// Return the system-level state directory path.
#[must_use]
pub fn system_state_dir() -> PathBuf {
    PathBuf::from(STATE_DIR)
}

#[cfg(target_os = "linux")]
#[must_use]
pub fn running_privileged_install() -> bool {
    false
}

#[cfg(not(target_os = "linux"))]
#[must_use]
pub fn running_privileged_install() -> bool {
    nix_is_root()
}

/// Print the action plan the user is about to confirm.
#[cfg(target_os = "linux")]
pub fn print_plan() {
    eprintln!("stt-guard Linux system install is not enabled yet.");
    eprintln!("The production layout is defined for:");
    eprintln!(
        "  • {} service user (no login shell, {STATE_DIR} home)",
        paths::SERVICE_USER
    );
    eprintln!(
        "  • root-owned binaries and hook library under {}/",
        paths::SYSTEM_BIN_DIR
    );
    eprintln!("  • service-owned state directory at {STATE_DIR}/");
    eprintln!(
        "  • service-owned log directory at {}/",
        paths::SYSTEM_LOG_DIR
    );
    eprintln!(
        "  • systemd daemon unit at {}",
        paths::SYSTEMD_DAEMON_UNIT_PATH
    );
    eprintln!("Activation is blocked until Linux OS-backed signer enrollment is implemented.");
}

/// Print the action plan the user is about to confirm.
#[cfg(not(target_os = "linux"))]
pub fn print_plan() {
    eprintln!("stt-guard will install a root-owned system guard and start {PLIST_LABEL}.");
    eprintln!("It will request sudo after enrolling your device-local macOS Keychain signer.");
}

/// Execute the full hardened installation. Must be run as root.
///
/// # Errors
///
/// Always returns an error on Linux because the hardened installer is not
/// implemented there yet.
#[cfg(target_os = "linux")]
pub fn run_install() -> Result<(), CliError> {
    Err(CliError::Other(
        "Linux hardened install is not implemented yet. \
         The systemd layout and health checks are defined, but production activation is blocked on OS-backed signer enrollment."
            .into(),
    ))
}

/// Execute the full hardened installation. Must be run as root.
///
/// # Errors
///
/// Returns an error when root privileges are missing or any install step fails.
#[cfg(not(target_os = "linux"))]
pub fn run_install() -> Result<(), CliError> {
    if !nix_is_root() {
        return run_install_with_privilege_escalation();
    }

    require_root()?;
    require_privileged_signer_handoff()?;

    let mut transaction = InstallTransaction::new()?;

    let result: Result<(), CliError> = (|| {
        let service_user = create_service_user()?;
        transaction.record_service_user(service_user.created);
        maybe_fail_install_step("after-create-service-user")?;

        deploy_binaries(&mut transaction)?;
        maybe_fail_install_step("after-deploy-binaries")?;

        create_directories(service_user.gid, &mut transaction)?;
        maybe_fail_install_step("after-create-directories")?;

        let enrollment = enroll_hardware_signer_for_install()?;
        record_hardware_signer_rollback(&mut transaction, enrollment.created);
        maybe_fail_install_step("after-enroll-signer")?;

        register_rule_signer(&enrollment, service_user.gid, &mut transaction)?;
        maybe_fail_install_step("after-register-signer")?;

        install_launchdaemon(&mut transaction)?;
        maybe_fail_install_step("after-install-launchdaemon")?;

        start_daemon(&mut transaction)?;
        maybe_fail_install_step("after-start-daemon")?;

        Ok(())
    })();

    if let Err(install_error) = result {
        eprintln!("\nstt-guard: system install failed: {install_error}");

        let rollback = transaction.rollback();
        eprintln!("stt-guard: {}", rollback.status_message());

        return Err(CliError::Other(format!(
            "system install failed: {install_error}; {}",
            rollback.error_suffix()
        )));
    }

    transaction.commit();
    eprintln!("\nstt-guard: system install complete.");
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn require_root() -> Result<(), CliError> {
    if !nix_is_root() {
        return Err(CliError::Other(
            "stt-guard system install requires root for the final deployment step".into(),
        ));
    }
    Ok(())
}

#[cfg(all(target_os = "macos", not(feature = "test-signer")))]
fn require_privileged_signer_handoff() -> Result<(), CliError> {
    if std::env::var_os(INSTALL_KEYCHAIN_ENROLLMENT_ENV).is_none() {
        return Err(CliError::Other(
            "run install-system without sudo; it will request privileges after enrolling the user signer"
                .into(),
        ));
    }

    Ok(())
}

#[cfg(any(
    all(not(target_os = "macos"), not(target_os = "linux")),
    all(target_os = "macos", feature = "test-signer")
))]
fn require_privileged_signer_handoff() -> Result<(), CliError> {
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn nix_is_root() -> bool {
    unsafe { libc::geteuid() == 0 }
}

#[cfg(not(target_os = "linux"))]
fn run_install_with_privilege_escalation() -> Result<(), CliError> {
    let enrollment = crate::hardware_signing::enroll_keychain_signer_for_init()?;
    let enrollment_json = serde_json::to_vec(&enrollment)
        .map_err(|e| CliError::Other(format!("encode Keychain enrollment: {e}")))?;
    let workspace = InstallWorkspace::create()?;
    let keychain_enrollment_path = workspace.path().join("keychain-enrollment.json");
    std::fs::write(&keychain_enrollment_path, enrollment_json).map_err(|e| {
        CliError::Other(format!("write {}: {e}", keychain_enrollment_path.display()))
    })?;

    let current_exe = std::env::current_exe()
        .map_err(|e| CliError::Other(format!("locate installer executable: {e}")))?;
    let mut command = Command::new("sudo");

    #[cfg(all(target_os = "macos", not(feature = "test-signer")))]
    command.arg(format!(
        "{INSTALL_KEYCHAIN_ENROLLMENT_ENV}={}",
        keychain_enrollment_path.display()
    ));

    let status = command
        .arg(current_exe)
        .arg("install-system")
        .arg("--yes")
        .status()
        .map_err(|e| CliError::Other(format!("run privileged installer: {e}")))?;

    if !status.success() {
        return Err(CliError::Other(format!(
            "privileged installer failed with status {status}"
        )));
    }

    Ok(())
}

#[cfg(all(target_os = "macos", feature = "test-signer"))]
fn enroll_hardware_signer_for_install() -> Result<HardwareSignerEnrollment, CliError> {
    crate::hardware_signing::enroll_keychain_signer_for_init()
}

#[cfg(all(target_os = "macos", not(feature = "test-signer")))]
fn enroll_hardware_signer_for_install() -> Result<HardwareSignerEnrollment, CliError> {
    let keychain_enrollment_path = std::env::var_os(INSTALL_KEYCHAIN_ENROLLMENT_ENV)
        .map(PathBuf::from)
        .ok_or_else(|| {
            CliError::Other(
                "run install-system without sudo so signer enrollment can happen before privilege escalation"
                    .into(),
            )
        })?;
    let enrollment_json = std::fs::read(&keychain_enrollment_path).map_err(|e| {
        CliError::Other(format!(
            "read Keychain enrollment {}: {e}",
            keychain_enrollment_path.display()
        ))
    })?;

    serde_json::from_slice(&enrollment_json)
        .map_err(|e| CliError::Other(format!("decode Keychain enrollment: {e}")))
}

#[cfg(all(not(target_os = "linux"), feature = "test-signer"))]
fn delete_hardware_signer_for_install() -> Result<(), CliError> {
    crate::hardware_signing::delete_keychain_signer_for_init()
}

#[cfg(all(not(target_os = "linux"), feature = "test-signer"))]
fn record_hardware_signer_rollback(transaction: &mut InstallTransaction, created: bool) {
    transaction.record_hardware_signer_key(created);
}

#[cfg(all(not(target_os = "linux"), not(feature = "test-signer")))]
fn record_hardware_signer_rollback(_transaction: &mut InstallTransaction, _created: bool) {
    // Production enrollment happens in the invoking user's keychain before
    // privilege escalation, outside the root-owned install transaction.
}

#[cfg(all(not(target_os = "linux"), not(target_os = "macos")))]
fn enroll_hardware_signer_for_install() -> Result<HardwareSignerEnrollment, CliError> {
    Err(CliError::Other(
        "hardened install is currently supported on macOS only".into(),
    ))
}

#[cfg(not(target_os = "linux"))]
struct ServiceUserInstall {
    gid: u32,
    created: bool,
}

#[cfg(not(target_os = "linux"))]
fn create_service_user() -> Result<ServiceUserInstall, CliError> {
    // Check if user already exists.
    let check = Command::new("dscl")
        .args([".", "-read", &format!("/Users/{SERVICE_USER}")])
        .output()
        .map_err(|e| CliError::Other(format!("dscl check: {e}")))?;

    let gid = if check.status.success() {
        eprintln!("  {SERVICE_USER} user already exists, verifying attributes");
        let gid = service_gid()?;
        set_service_user_attributes(gid)?;
        ServiceUserInstall {
            gid,
            created: false,
        }
    } else {
        eprintln!("  Creating {SERVICE_USER} service user...");

        // Find an unused UID in the system range (400-499).
        let uid = find_available_uid()?;
        let uid_str = uid.to_string();

        let steps: &[(&[&str], &str)] = &[
            (
                &[".", "-create", &format!("/Users/{SERVICE_USER}")],
                "create user record",
            ),
            (
                &[
                    ".",
                    "-create",
                    &format!("/Users/{SERVICE_USER}"),
                    "UniqueID",
                    &uid_str,
                ],
                "set uid",
            ),
            (
                &[
                    ".",
                    "-create",
                    &format!("/Users/{SERVICE_USER}"),
                    "PrimaryGroupID",
                    &uid_str,
                ],
                "set gid",
            ),
        ];

        for (args, description) in steps {
            run_cmd("dscl", args, description)?;
        }

        set_service_user_attributes(uid)?;
        ServiceUserInstall {
            gid: uid,
            created: true,
        }
    };

    Ok(gid)
}

#[cfg(not(target_os = "linux"))]
fn set_service_user_attributes(gid: u32) -> Result<(), CliError> {
    let gid_str = gid.to_string();
    let user = format!("/Users/{SERVICE_USER}");
    let steps: &[(&str, &str, &str)] = &[
        ("UserShell", "/usr/bin/false", "set shell"),
        ("RealName", SERVICE_USER_REALNAME, "set realname"),
        ("PrimaryGroupID", &gid_str, "set gid"),
        ("NFSHomeDirectory", "/var/empty", "set home"),
    ];

    for (attr, value, description) in steps {
        ensure_record_attr(&user, attr, value, description)?;
    }

    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn ensure_record_attr(
    record: &str,
    attr: &str,
    expected: &str,
    description: &str,
) -> Result<(), CliError> {
    if service_record_attr_matches(record, attr, expected)? {
        return Ok(());
    }

    let _ = Command::new("dscl")
        .args([".", "-delete", record, attr])
        .output();
    run_cmd(
        "dscl",
        &[".", "-create", record, attr, expected],
        description,
    )
}

#[cfg(not(target_os = "linux"))]
fn service_record_attr_matches(record: &str, attr: &str, expected: &str) -> Result<bool, CliError> {
    let output = Command::new("dscl")
        .args([".", "-read", record, attr])
        .output()
        .map_err(|e| CliError::Other(format!("read {record} {attr}: {e}")))?;

    if !output.status.success() {
        return Ok(false);
    }

    Ok(
        dscl_attribute_values(&String::from_utf8_lossy(&output.stdout), attr)
            .iter()
            .any(|value| value == expected),
    )
}

#[cfg(not(target_os = "linux"))]
fn dscl_attribute_values(output: &str, attr: &str) -> Vec<String> {
    let Some(first_line) = output.lines().next() else {
        return Vec::new();
    };
    let Some(rest) = first_line.strip_prefix(&format!("{attr}:")) else {
        return Vec::new();
    };

    let inline = rest.trim();
    if !inline.is_empty() {
        return vec![inline.to_string()];
    }

    output
        .lines()
        .skip(1)
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(ToOwned::to_owned)
        .collect()
}

#[cfg(not(target_os = "linux"))]
fn service_gid() -> Result<u32, CliError> {
    let output = Command::new("id")
        .args(["-g", SERVICE_USER])
        .output()
        .map_err(|e| CliError::Other(format!("read {SERVICE_USER} gid: {e}")))?;
    if !output.status.success() {
        return Err(CliError::Other(format!(
            "read {SERVICE_USER} gid failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    stdout.trim().parse::<u32>().map_err(|e| {
        CliError::Other(format!(
            "read {SERVICE_USER} gid returned malformed value {:?}: {e}",
            stdout.trim()
        ))
    })
}

#[cfg(not(target_os = "linux"))]
fn find_available_uid() -> Result<u32, CliError> {
    for uid in 400..500 {
        let check = Command::new("dscl")
            .args([".", "-search", "/Users", "UniqueID", &uid.to_string()])
            .output()
            .map_err(|e| CliError::Other(format!("dscl uid search: {e}")))?;
        let stdout = String::from_utf8_lossy(&check.stdout);
        if stdout.trim().is_empty() {
            return Ok(uid);
        }
    }
    Err(CliError::Other(
        "no available UID in range 400-499 for service user".into(),
    ))
}

#[cfg(not(target_os = "linux"))]
fn deploy_binaries(transaction: &mut InstallTransaction) -> Result<(), CliError> {
    eprintln!("  Deploying binaries to {BIN_DIR}/...");

    transaction.record_directory_created(Path::new(BIN_DIR))?;
    transaction.record_path_metadata(Path::new(BIN_DIR))?;
    std::fs::create_dir_all(BIN_DIR)
        .map_err(|e| CliError::Other(format!("create {BIN_DIR}: {e}")))?;

    let source_dir = source_bin_dir()?;

    for bin_name in BINARIES {
        let src = source_dir.join(bin_name);
        let dst = Path::new(BIN_DIR).join(bin_name);
        if !src.exists() {
            return Err(CliError::Other(format!(
                "source binary not found: {}",
                src.display()
            )));
        }
        transaction.record_file_replacement(&dst)?;
        std::fs::copy(&src, &dst).map_err(|e| {
            CliError::Other(format!("copy {} -> {}: {e}", src.display(), dst.display()))
        })?;
    }

    let dylib_src = hook_dylib_source_path(&source_dir)?;
    let dylib_dst = Path::new(BIN_DIR).join(DYLIB);
    transaction.record_file_replacement(&dylib_dst)?;
    std::fs::copy(&dylib_src, &dylib_dst).map_err(|e| {
        CliError::Other(format!(
            "copy {} -> {}: {e}",
            dylib_src.display(),
            dylib_dst.display()
        ))
    })?;

    // Set ownership: root:wheel, 755 for binaries, 644 for dylib.
    run_cmd("chown", &["root:wheel", BIN_DIR], "set binary ownership")?;
    run_cmd("chmod", &["755", BIN_DIR], "set binary dir permissions")?;
    for bin_name in BINARIES {
        let path = Path::new(BIN_DIR).join(bin_name);
        run_cmd(
            "chown",
            &["root:wheel", &path.to_string_lossy()],
            "set binary ownership",
        )?;
        run_cmd(
            "chmod",
            &["755", &path.to_string_lossy()],
            "set binary permissions",
        )?;
    }
    let dylib_dst = Path::new(BIN_DIR).join(DYLIB);
    if dylib_dst.exists() {
        run_cmd(
            "chown",
            &["root:wheel", &dylib_dst.to_string_lossy()],
            "set dylib ownership",
        )?;
        run_cmd(
            "chmod",
            &["644", &dylib_dst.to_string_lossy()],
            "set dylib permissions",
        )?;
    }

    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn source_bin_dir() -> Result<PathBuf, CliError> {
    // The running stt-guard binary's parent directory contains the build artifacts.
    let exe = std::env::current_exe().map_err(|e| CliError::Other(format!("current_exe: {e}")))?;
    exe.parent()
        .map(std::path::Path::to_path_buf)
        .ok_or_else(|| CliError::Other("cannot determine source binary directory".into()))
}

#[cfg(not(target_os = "linux"))]
fn hook_dylib_source_path(source_dir: &Path) -> Result<PathBuf, CliError> {
    for candidate in [DYLIB, CARGO_HOOK_DYLIB] {
        let path = source_dir.join(candidate);
        if path.exists() {
            return Ok(path);
        }
    }

    Err(CliError::Other(format!(
        "source hook library not found: expected {} or {} in {}",
        DYLIB,
        CARGO_HOOK_DYLIB,
        source_dir.display()
    )))
}

#[cfg(not(target_os = "linux"))]
fn create_directories(
    service_gid: u32,
    transaction: &mut InstallTransaction,
) -> Result<(), CliError> {
    let service_owner = format!("{SERVICE_USER}:{service_gid}");

    eprintln!("  Creating state directory at {STATE_DIR}/...");
    transaction.record_directory_created(Path::new(STATE_DIR))?;
    transaction.record_path_metadata(Path::new(STATE_DIR))?;
    std::fs::create_dir_all(STATE_DIR)
        .map_err(|e| CliError::Other(format!("create {STATE_DIR}: {e}")))?;
    run_cmd(
        "chown",
        &[&service_owner, STATE_DIR],
        "set state dir ownership",
    )?;
    run_cmd("chmod", &["711", STATE_DIR], "set state dir permissions")?;

    eprintln!("  Creating log directory at {LOG_DIR}/...");
    transaction.record_directory_created(Path::new(LOG_DIR))?;
    transaction.record_path_metadata(Path::new(LOG_DIR))?;
    std::fs::create_dir_all(LOG_DIR)
        .map_err(|e| CliError::Other(format!("create {LOG_DIR}: {e}")))?;
    run_cmd("chown", &[&service_owner, LOG_DIR], "set log dir ownership")?;
    run_cmd("chmod", &["711", LOG_DIR], "set log dir permissions")?;

    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn register_rule_signer(
    enrollment: &HardwareSignerEnrollment,
    service_gid: u32,
    transaction: &mut InstallTransaction,
) -> Result<(), CliError> {
    eprintln!(
        "  Registering trusted rule signer {}...",
        enrollment.public_key_sha256
    );
    write_trusted_signer_manifest(enrollment, transaction)?;
    let db_path = paths::db_path(Path::new(STATE_DIR));
    transaction.record_sqlite_replacement(&db_path)?;
    let store = guard_daemon::rule_store::RuleStore::open(&db_path)
        .map_err(|e| CliError::Other(format!("open rule store for signer enrollment: {e}")))?;
    store
        .register_trusted_rule_signer_key(
            &enrollment.public_key_sha256,
            &enrollment.signer_kind,
            &enrollment.public_key_x963,
            &enrollment.label,
        )
        .map_err(|e| CliError::Other(format!("register trusted rule signer: {e}")))?;
    let service_owner = format!("{SERVICE_USER}:{service_gid}");
    run_cmd(
        "chown",
        &["-R", &service_owner, STATE_DIR],
        "set state dir ownership after signer enrollment",
    )?;
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn write_trusted_signer_manifest(
    enrollment: &HardwareSignerEnrollment,
    transaction: &mut InstallTransaction,
) -> Result<(), CliError> {
    let path = paths::trusted_rule_signers_path();
    let content = format!(
        "# stt-guard trusted OS-backed rule signers v1\n{}\t{}\t{}\t{}\n",
        enrollment.public_key_sha256,
        enrollment.signer_kind,
        hex_lower(&enrollment.public_key_x963),
        enrollment.label.replace(['\t', '\n'], " "),
    );
    transaction.record_file_replacement(&path)?;
    if let Ok(meta) = std::fs::symlink_metadata(&path) {
        if meta.file_type().is_dir() {
            return Err(CliError::Other(format!(
                "trusted signer manifest path is a directory: {}",
                path.display()
            )));
        }
        std::fs::remove_file(&path)
            .map_err(|e| CliError::Other(format!("remove existing {}: {e}", path.display())))?;
    }
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o644)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&path)
        .map_err(|e| CliError::Other(format!("create {}: {e}", path.display())))?;
    file.write_all(content.as_bytes())
        .map_err(|e| CliError::Other(format!("write {}: {e}", path.display())))?;
    run_cmd(
        "chown",
        &["root:wheel", &path.to_string_lossy()],
        "set trusted signer manifest ownership",
    )?;
    run_cmd(
        "chmod",
        &["644", &path.to_string_lossy()],
        "set trusted signer manifest permissions",
    )?;
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 0x0f) as usize] as char);
    }
    s
}

#[cfg(not(target_os = "linux"))]
fn install_launchdaemon(transaction: &mut InstallTransaction) -> Result<(), CliError> {
    eprintln!("  Installing LaunchDaemon ({PLIST_LABEL})...");

    let plist_content = crate::install::health::expected_launchdaemon_plist();

    transaction.record_file_replacement(Path::new(PLIST_PATH))?;
    std::fs::write(PLIST_PATH, plist_content)
        .map_err(|e| CliError::Other(format!("write {PLIST_PATH}: {e}")))?;
    run_cmd("chown", &["root:wheel", PLIST_PATH], "set plist ownership")?;
    run_cmd("chmod", &["644", PLIST_PATH], "set plist permissions")?;

    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn start_daemon(transaction: &mut InstallTransaction) -> Result<(), CliError> {
    eprintln!("  Starting daemon...");

    // Unload first (ignore failure — may not be loaded yet).
    let _ = Command::new("launchctl")
        .args(["bootout", &format!("system/{PLIST_LABEL}")])
        .output();

    run_cmd(
        "launchctl",
        &["bootstrap", "system", PLIST_PATH],
        "bootstrap LaunchDaemon",
    )?;

    transaction.record_started_launchdaemon();

    Ok(())
}

#[cfg(not(target_os = "linux"))]
struct InstallTransaction {
    rollback_actions: Vec<RollbackAction>,
    backup_dir: PathBuf,
    pre_existing_guard_state: bool,
    committed: bool,
}

#[cfg(not(target_os = "linux"))]
impl InstallTransaction {
    fn new() -> Result<Self, CliError> {
        let backup_nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |duration| duration.as_nanos());
        let backup_dir = std::env::temp_dir().join(format!(
            "stt-guard-install-rollback-{}-{backup_nonce}",
            std::process::id(),
        ));
        if backup_dir.exists() {
            std::fs::remove_dir_all(&backup_dir).map_err(|e| {
                CliError::Other(format!("remove stale {}: {e}", backup_dir.display()))
            })?;
        }
        std::fs::create_dir(&backup_dir)
            .map_err(|e| CliError::Other(format!("create {}: {e}", backup_dir.display())))?;

        let trusted_rule_signers_path = paths::trusted_rule_signers_path();
        let pre_existing_guard_state = [
            Path::new(BIN_DIR),
            Path::new(STATE_DIR),
            Path::new(LOG_DIR),
            Path::new(PLIST_PATH),
            trusted_rule_signers_path.as_path(),
        ]
        .iter()
        .any(|path| path.exists());

        let mut rollback_actions = Vec::new();
        if launchdaemon_loaded() {
            rollback_actions.push(RollbackAction::BootstrapLaunchDaemon);
        }

        Ok(Self {
            rollback_actions,
            backup_dir,
            pre_existing_guard_state,
            committed: false,
        })
    }

    #[cfg(test)]
    fn new_without_ambient_system_actions() -> Result<Self, CliError> {
        let mut transaction = Self::new()?;
        transaction.rollback_actions.clear();

        Ok(transaction)
    }

    fn commit(mut self) {
        self.committed = true;
        self.remove_backup_dir_after_success();
    }

    fn rollback(mut self) -> RollbackReport {
        let mut failures = Vec::new();

        while let Some(action) = self.rollback_actions.pop() {
            if let Err(err) = action.rollback() {
                failures.push(err);
            }
        }

        if let Err(err) = std::fs::remove_dir_all(&self.backup_dir)
            && self.backup_dir.exists()
        {
            failures.push(format!("remove {}: {err}", self.backup_dir.display()));
        }

        RollbackReport { failures }
    }

    fn record_service_user(&mut self, created: bool) {
        if created && !self.pre_existing_guard_state {
            self.rollback_actions
                .push(RollbackAction::RemoveServiceUser);
        }
    }

    fn record_started_launchdaemon(&mut self) {
        self.rollback_actions
            .push(RollbackAction::BootoutLaunchDaemon);
    }

    #[cfg(feature = "test-signer")]
    fn record_hardware_signer_key(&mut self, created: bool) {
        if created {
            self.rollback_actions
                .push(RollbackAction::RemoveHardwareSignerKey);
        }
    }

    fn record_directory_created(&mut self, path: &Path) -> Result<(), CliError> {
        match std::fs::symlink_metadata(path) {
            Ok(metadata) => {
                if metadata.file_type().is_symlink() {
                    return Err(CliError::Other(format!(
                        "refusing to use symlinked install directory {}",
                        path.display()
                    )));
                }
                if !metadata.is_dir() {
                    return Err(CliError::Other(format!(
                        "install directory path is not a directory: {}",
                        path.display()
                    )));
                }
            }
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                self.rollback_actions
                    .push(RollbackAction::RemoveDirectoryIfCreated(path.to_path_buf()));
            }
            Err(err) => {
                return Err(CliError::Other(format!(
                    "inspect {} before install: {err}",
                    path.display()
                )));
            }
        }

        Ok(())
    }

    fn record_path_metadata(&mut self, path: &Path) -> Result<(), CliError> {
        match std::fs::symlink_metadata(path) {
            Ok(metadata) => {
                let path_metadata = PathMetadata::from_metadata(&metadata);
                self.rollback_actions.push(RollbackAction::RestoreMetadata {
                    path: path.to_path_buf(),
                    metadata: path_metadata,
                });
            }
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
            Err(err) => {
                return Err(CliError::Other(format!(
                    "inspect {} metadata before install: {err}",
                    path.display()
                )));
            }
        }

        Ok(())
    }

    fn record_file_replacement(&mut self, path: &Path) -> Result<(), CliError> {
        match std::fs::symlink_metadata(path) {
            Ok(metadata) => {
                if metadata.file_type().is_symlink() {
                    return Err(CliError::Other(format!(
                        "refusing to replace symlinked install file {}",
                        path.display()
                    )));
                }
                if !metadata.is_file() {
                    return Err(CliError::Other(format!(
                        "install file path is not a regular file: {}",
                        path.display()
                    )));
                }

                let backup = self.next_backup_path();
                std::fs::copy(path, &backup).map_err(|e| {
                    CliError::Other(format!(
                        "backup {} -> {}: {e}",
                        path.display(),
                        backup.display()
                    ))
                })?;
                self.rollback_actions.push(RollbackAction::RestoreFile {
                    path: path.to_path_buf(),
                    backup,
                    metadata: PathMetadata::from_metadata(&metadata),
                });
            }
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                self.rollback_actions
                    .push(RollbackAction::RemoveFileIfCreated(path.to_path_buf()));
            }
            Err(err) => {
                return Err(CliError::Other(format!(
                    "inspect {} before replacement: {err}",
                    path.display()
                )));
            }
        }

        Ok(())
    }

    fn record_sqlite_replacement(&mut self, db_path: &Path) -> Result<(), CliError> {
        self.record_file_replacement(db_path)?;
        for sidecar_path in sqlite_sidecar_paths(db_path) {
            self.record_file_replacement(&sidecar_path)?;
        }

        Ok(())
    }

    fn next_backup_path(&self) -> PathBuf {
        self.backup_dir
            .join(format!("backup-{}", self.rollback_actions.len()))
    }

    fn remove_backup_dir_after_success(&self) {
        if let Err(err) = std::fs::remove_dir_all(&self.backup_dir)
            && self.backup_dir.exists()
        {
            eprintln!(
                "stt-guard: warning: could not remove rollback backup directory {}: {err}",
                self.backup_dir.display()
            );
        }
    }
}

#[cfg(not(target_os = "linux"))]
struct InstallWorkspace {
    path: PathBuf,
}

#[cfg(not(target_os = "linux"))]
impl InstallWorkspace {
    fn create() -> Result<Self, CliError> {
        let workspace_nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |duration| duration.as_nanos());
        let path = std::env::temp_dir().join(format!(
            "stt-guard-install-{}-{workspace_nonce}",
            std::process::id(),
        ));

        std::fs::create_dir(&path)
            .map_err(|e| CliError::Other(format!("create {}: {e}", path.display())))?;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700))
            .map_err(|e| CliError::Other(format!("chmod {}: {e}", path.display())))?;

        Ok(Self { path })
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

#[cfg(not(target_os = "linux"))]
impl Drop for InstallWorkspace {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

#[cfg(not(target_os = "linux"))]
impl Drop for InstallTransaction {
    fn drop(&mut self) {
        if self.committed {
            return;
        }

        if self.backup_dir.exists() {
            eprintln!(
                "stt-guard: warning: abandoned rollback backup directory {}",
                self.backup_dir.display()
            );
        }
    }
}

#[cfg(not(target_os = "linux"))]
#[derive(Clone, Copy)]
struct PathMetadata {
    uid: u32,
    gid: u32,
    mode: u32,
}

#[cfg(not(target_os = "linux"))]
impl PathMetadata {
    fn from_metadata(metadata: &std::fs::Metadata) -> Self {
        Self {
            uid: metadata.uid(),
            gid: metadata.gid(),
            mode: metadata.mode() & 0o7777,
        }
    }

    fn restore(self, path: &Path) -> Result<(), String> {
        let owner = format!("{}:{}", self.uid, self.gid);
        let mode = format!("{:o}", self.mode);
        run_cmd("chown", &[&owner, &path.to_string_lossy()], "restore owner")
            .map_err(|e| e.to_string())?;
        run_cmd("chmod", &[&mode, &path.to_string_lossy()], "restore mode")
            .map_err(|e| e.to_string())
    }
}

#[cfg(not(target_os = "linux"))]
enum RollbackAction {
    RemoveFileIfCreated(PathBuf),
    RestoreFile {
        path: PathBuf,
        backup: PathBuf,
        metadata: PathMetadata,
    },
    RemoveDirectoryIfCreated(PathBuf),
    RestoreMetadata {
        path: PathBuf,
        metadata: PathMetadata,
    },
    BootoutLaunchDaemon,
    BootstrapLaunchDaemon,
    RemoveServiceUser,
    #[cfg(feature = "test-signer")]
    RemoveHardwareSignerKey,
}

#[cfg(not(target_os = "linux"))]
impl RollbackAction {
    fn rollback(self) -> Result<(), String> {
        match self {
            Self::RemoveFileIfCreated(path) => remove_file_if_present(&path),
            Self::RestoreFile {
                path,
                backup,
                metadata,
            } => restore_file_from_backup(&path, &backup, metadata),
            Self::RemoveDirectoryIfCreated(path) => remove_directory_if_empty(&path),
            Self::RestoreMetadata { path, metadata } => {
                if !path.exists() {
                    return Ok(());
                }
                metadata.restore(&path)
            }
            Self::BootoutLaunchDaemon => {
                let _ = Command::new("launchctl")
                    .args(["bootout", &format!("system/{PLIST_LABEL}")])
                    .output();
                Ok(())
            }
            Self::BootstrapLaunchDaemon => run_cmd(
                "launchctl",
                &["bootstrap", "system", PLIST_PATH],
                "restore pre-existing LaunchDaemon",
            )
            .map_err(|e| e.to_string()),
            Self::RemoveServiceUser => run_cmd(
                "dscl",
                &[".", "-delete", &format!("/Users/{SERVICE_USER}")],
                "remove service user created by failed install",
            )
            .map_err(|e| e.to_string()),
            #[cfg(feature = "test-signer")]
            Self::RemoveHardwareSignerKey => {
                delete_hardware_signer_for_install().map_err(|e| e.to_string())
            }
        }
    }
}

#[cfg(not(target_os = "linux"))]
struct RollbackReport {
    failures: Vec<String>,
}

#[cfg(not(target_os = "linux"))]
impl RollbackReport {
    fn status_message(&self) -> String {
        if self.failures.is_empty() {
            return "rollback completed.".to_string();
        }

        format!(
            "rollback partially completed with {} failure(s): {}",
            self.failures.len(),
            self.failures.join("; ")
        )
    }

    fn error_suffix(&self) -> String {
        if self.failures.is_empty() {
            return "rollback completed".to_string();
        }

        format!(
            "rollback partially completed with {} failure(s): {}",
            self.failures.len(),
            self.failures.join("; ")
        )
    }
}

#[cfg(not(target_os = "linux"))]
fn restore_file_from_backup(
    path: &Path,
    backup: &Path,
    metadata: PathMetadata,
) -> Result<(), String> {
    if let Ok(current_metadata) = std::fs::symlink_metadata(path) {
        if current_metadata.file_type().is_symlink() || current_metadata.is_file() {
            std::fs::remove_file(path)
                .map_err(|e| format!("remove changed {}: {e}", path.display()))?;
        } else {
            return Err(format!(
                "cannot restore {}; current path is not a file",
                path.display()
            ));
        }
    }

    std::fs::copy(backup, path).map_err(|e| {
        format!(
            "restore {} from backup {}: {e}",
            path.display(),
            backup.display()
        )
    })?;
    metadata.restore(path)?;
    std::fs::remove_file(backup)
        .map_err(|e| format!("remove consumed backup {}: {e}", backup.display()))
}

#[cfg(not(target_os = "linux"))]
fn remove_file_if_present(path: &Path) -> Result<(), String> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() || metadata.is_file() {
                std::fs::remove_file(path)
                    .map_err(|e| format!("remove created file {}: {e}", path.display()))?;
            }
            Ok(())
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(format!("inspect created file {}: {err}", path.display())),
    }
}

#[cfg(not(target_os = "linux"))]
fn remove_directory_if_empty(path: &Path) -> Result<(), String> {
    match std::fs::remove_dir(path) {
        Ok(()) => Ok(()),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(format!(
            "remove created directory {}: {err}",
            path.display()
        )),
    }
}

#[cfg(not(target_os = "linux"))]
fn launchdaemon_loaded() -> bool {
    Command::new("launchctl")
        .args(["print", &format!("system/{PLIST_LABEL}")])
        .output()
        .is_ok_and(|output| output.status.success())
}

#[cfg(not(target_os = "linux"))]
fn sqlite_sidecar_paths(db_path: &Path) -> [PathBuf; 2] {
    [
        PathBuf::from(format!("{}-wal", db_path.display())),
        PathBuf::from(format!("{}-shm", db_path.display())),
    ]
}

#[cfg(all(not(target_os = "linux"), feature = "test-signer"))]
fn maybe_fail_install_step(step: &str) -> Result<(), CliError> {
    if std::env::var(INSTALL_FAIL_STEP_ENV).as_deref() == Ok(step) {
        return Err(CliError::Other(format!(
            "injected install failure at {step}"
        )));
    }

    Ok(())
}

#[cfg(all(not(target_os = "linux"), not(feature = "test-signer")))]
#[expect(
    clippy::unnecessary_wraps,
    reason = "run_install uses one failpoint call shape in test and production builds"
)]
fn maybe_fail_install_step(_step: &str) -> Result<(), CliError> {
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn run_cmd(program: &str, args: &[&str], description: &str) -> Result<(), CliError> {
    let output = Command::new(program)
        .args(args)
        .output()
        .map_err(|e| CliError::Other(format!("{description}: {e}")))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(CliError::Other(format!("{description} failed: {stderr}")));
    }
    Ok(())
}

#[cfg(test)]
#[cfg(not(target_os = "linux"))]
mod tests {
    use std::io::Write;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn rollback_restores_replaced_file_and_removes_created_file() {
        let temp = tempfile::tempdir().expect("tempdir");
        let existing_path = temp.path().join("existing");
        let created_path = temp.path().join("created");

        {
            let mut existing = std::fs::File::create(&existing_path).expect("create existing");
            existing.write_all(b"before").expect("write existing");
        }
        std::fs::set_permissions(&existing_path, std::fs::Permissions::from_mode(0o600))
            .expect("set mode");

        let mut transaction =
            super::InstallTransaction::new_without_ambient_system_actions().expect("transaction");
        transaction
            .record_file_replacement(&existing_path)
            .expect("record existing");
        std::fs::write(&existing_path, b"after").expect("replace existing");

        transaction
            .record_file_replacement(&created_path)
            .expect("record created");
        std::fs::write(&created_path, b"created").expect("write created");

        let rollback = transaction.rollback();

        assert!(
            rollback.failures.is_empty(),
            "unexpected rollback failures: {:?}",
            rollback.failures
        );
        assert_eq!(
            std::fs::read(&existing_path).expect("read restored"),
            b"before"
        );
        assert!(!created_path.exists(), "created file should be removed");
        assert_eq!(
            std::fs::metadata(&existing_path)
                .expect("metadata")
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
    }

    #[test]
    fn rollback_report_separates_success_and_partial_failure() {
        let success = super::RollbackReport {
            failures: Vec::new(),
        };
        assert_eq!(success.status_message(), "rollback completed.");
        assert_eq!(success.error_suffix(), "rollback completed");

        let partial = super::RollbackReport {
            failures: vec!["restore failed".to_string()],
        };
        assert!(
            partial
                .status_message()
                .contains("rollback partially completed with 1 failure(s)")
        );
    }

    #[test]
    fn sqlite_sidecar_paths_follow_sqlite_wal_naming() {
        let paths = super::sqlite_sidecar_paths(std::path::Path::new("/tmp/stt-guard.db"));

        assert_eq!(paths[0], std::path::PathBuf::from("/tmp/stt-guard.db-wal"));
        assert_eq!(paths[1], std::path::PathBuf::from("/tmp/stt-guard.db-shm"));
    }
}

#[cfg(test)]
#[cfg(target_os = "linux")]
mod tests {
    #[test]
    fn linux_hardened_install_is_explicitly_unsupported() {
        let err = super::run_install().expect_err("Linux install should be gated");

        assert!(
            err.to_string()
                .contains("Linux hardened install is not implemented yet"),
            "unexpected error: {err}"
        );
    }
}
