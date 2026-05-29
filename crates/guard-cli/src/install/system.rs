//! Hardened system-level installation.
//!
//! Creates the `_stt_guard` service user, deploys root-owned binaries to
//! `/usr/local/libexec/stt-guard/`, creates state and log directories owned
//! by `_stt_guard`, installs a `LaunchDaemon`, and starts it.

#[cfg(not(target_os = "linux"))]
use std::io::Write;
#[cfg(not(target_os = "linux"))]
use std::os::unix::fs::OpenOptionsExt;
#[cfg(not(target_os = "linux"))]
use std::path::Path;
use std::path::PathBuf;
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

/// Print the action plan the user is about to confirm.
#[cfg(target_os = "linux")]
pub fn print_plan() {
    eprintln!("stt-guard Linux system install is not enabled yet.");
    eprintln!("The production layout is defined for:");
    eprintln!("  • {SERVICE_USER} service user (no login shell, {STATE_DIR} home)");
    eprintln!("  • root-owned binaries and hook library under {BIN_DIR}/");
    eprintln!("  • service-owned state directory at {STATE_DIR}/");
    eprintln!("  • service-owned log directory at {LOG_DIR}/");
    eprintln!(
        "  • systemd daemon unit at {}",
        paths::SYSTEMD_DAEMON_UNIT_PATH
    );
    eprintln!(
        "Activation is blocked until Linux hardware-backed signer enrollment is implemented."
    );
}

/// Print the action plan the user is about to confirm.
#[cfg(not(target_os = "linux"))]
pub fn print_plan() {
    eprintln!("stt-guard system install will:");
    eprintln!("  • Create {SERVICE_USER} service user (no login shell, /var/empty home)");
    eprintln!("  • Copy binaries to {BIN_DIR}/ (root:wheel, 755)");
    eprintln!("  • Copy hook dylib to {BIN_DIR}/ (root:wheel, 644)");
    eprintln!("  • Create state directory at {STATE_DIR}/");
    eprintln!("  • Create log directory at {LOG_DIR}/");
    eprintln!("  • Enroll a non-exportable Secure Enclave rule-signing key");
    eprintln!("  • Register the hardware-backed public signer with the daemon state");
    eprintln!("  • Install LaunchDaemon ({PLIST_LABEL})");
    eprintln!("  • Start the daemon");
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
         The systemd layout and health checks are defined, but production activation is blocked on hardware-backed signer enrollment."
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
    require_root()?;
    let service_gid = create_service_user()?;
    deploy_binaries()?;
    create_directories(service_gid)?;
    let enrollment = crate::hardware_signing::enroll_secure_enclave_for_init()?;
    register_rule_signer(&enrollment, service_gid)?;
    install_launchdaemon()?;
    start_daemon()?;
    eprintln!("\nstt-guard: system install complete.");
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn require_root() -> Result<(), CliError> {
    if !nix_is_root() {
        return Err(CliError::Other(
            "stt-guard system install requires root. Run the installer or stt-guard update.".into(),
        ));
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn nix_is_root() -> bool {
    unsafe { libc::geteuid() == 0 }
}

#[cfg(not(target_os = "linux"))]
fn create_service_user() -> Result<u32, CliError> {
    // Check if user already exists.
    let check = Command::new("dscl")
        .args([".", "-read", &format!("/Users/{SERVICE_USER}")])
        .output()
        .map_err(|e| CliError::Other(format!("dscl check: {e}")))?;

    let gid = if check.status.success() {
        eprintln!("  {SERVICE_USER} user already exists, verifying attributes");
        let gid = service_gid()?;
        set_service_user_attributes(gid)?;
        gid
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
        uid
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
fn deploy_binaries() -> Result<(), CliError> {
    eprintln!("  Deploying binaries to {BIN_DIR}/...");

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
        std::fs::copy(&src, &dst).map_err(|e| {
            CliError::Other(format!("copy {} -> {}: {e}", src.display(), dst.display()))
        })?;
    }

    // Deploy the hook dylib.
    let dylib_src = source_dir.join(DYLIB);
    if dylib_src.exists() {
        let dylib_dst = Path::new(BIN_DIR).join(DYLIB);
        std::fs::copy(&dylib_src, &dylib_dst).map_err(|e| {
            CliError::Other(format!(
                "copy {} -> {}: {e}",
                dylib_src.display(),
                dylib_dst.display()
            ))
        })?;
    }

    // Set ownership: root:wheel, 755 for binaries, 644 for dylib.
    run_cmd(
        "chown",
        &["-R", "root:wheel", BIN_DIR],
        "set binary ownership",
    )?;
    run_cmd("chmod", &["755", BIN_DIR], "set binary dir permissions")?;
    for bin_name in BINARIES {
        let path = Path::new(BIN_DIR).join(bin_name);
        run_cmd(
            "chmod",
            &["755", &path.to_string_lossy()],
            "set binary permissions",
        )?;
    }
    let dylib_dst = Path::new(BIN_DIR).join(DYLIB);
    if dylib_dst.exists() {
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
fn create_directories(service_gid: u32) -> Result<(), CliError> {
    let service_owner = format!("{SERVICE_USER}:{service_gid}");

    eprintln!("  Creating state directory at {STATE_DIR}/...");
    std::fs::create_dir_all(STATE_DIR)
        .map_err(|e| CliError::Other(format!("create {STATE_DIR}: {e}")))?;
    run_cmd(
        "chown",
        &[&service_owner, STATE_DIR],
        "set state dir ownership",
    )?;
    run_cmd("chmod", &["711", STATE_DIR], "set state dir permissions")?;

    eprintln!("  Creating log directory at {LOG_DIR}/...");
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
) -> Result<(), CliError> {
    eprintln!(
        "  Registering hardware-backed rule signer {}...",
        enrollment.public_key_sha256
    );
    write_trusted_signer_manifest(enrollment)?;
    let db_path = paths::db_path(Path::new(STATE_DIR));
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
fn write_trusted_signer_manifest(enrollment: &HardwareSignerEnrollment) -> Result<(), CliError> {
    let path = paths::trusted_rule_signers_path();
    let content = format!(
        "# stt-guard trusted hardware-backed rule signers v1\n{}\t{}\t{}\t{}\n",
        enrollment.public_key_sha256,
        enrollment.signer_kind,
        hex_lower(&enrollment.public_key_x963),
        enrollment.label.replace(['\t', '\n'], " "),
    );
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
fn install_launchdaemon() -> Result<(), CliError> {
    eprintln!("  Installing LaunchDaemon ({PLIST_LABEL})...");

    let plist_content = crate::install::health::expected_launchdaemon_plist();

    std::fs::write(PLIST_PATH, plist_content)
        .map_err(|e| CliError::Other(format!("write {PLIST_PATH}: {e}")))?;
    run_cmd("chown", &["root:wheel", PLIST_PATH], "set plist ownership")?;
    run_cmd("chmod", &["644", PLIST_PATH], "set plist permissions")?;

    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn start_daemon() -> Result<(), CliError> {
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
