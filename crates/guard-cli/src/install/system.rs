//! Hardened system-level installation.
//!
//! Creates the `_stt_guard` service user, deploys root-owned binaries to
//! `/usr/local/libexec/stt-guard/`, creates state and log directories owned
//! by `_stt_guard`, installs a LaunchDaemon, and starts it.

use std::path::{Path, PathBuf};
use std::process::Command;

use crate::CliError;

const SERVICE_USER: &str = "_stt_guard";
const SERVICE_USER_REALNAME: &str = "Stentorian Guard Daemon";

const BIN_DIR: &str = "/usr/local/libexec/stt-guard";
const STATE_DIR: &str = "/Library/Application Support/Stentorian Guard";
const LOG_DIR: &str = "/var/log/stt-guard";
const PLIST_LABEL: &str = "io.stentorian.guard.daemon";
const PLIST_PATH: &str = "/Library/LaunchDaemons/io.stentorian.guard.daemon.plist";

const BINARIES: &[&str] = &["stt-guard", "stt-guard-daemon"];
const DYLIB: &str = "stt-guard-hook.dylib";

/// Check whether the hardened installation is present.
/// Returns true if the deployed daemon binary exists under the system bin dir.
pub fn is_installed() -> bool {
    Path::new(BIN_DIR).join("stt-guard-daemon").exists()
}

/// Return the system-level state directory path.
pub fn system_state_dir() -> PathBuf {
    PathBuf::from(STATE_DIR)
}

/// Print the action plan the user is about to confirm.
pub fn print_plan() {
    eprintln!("stt-guard init will:");
    eprintln!("  • Create {SERVICE_USER} service user (no login shell, /var/empty home)");
    eprintln!("  • Copy binaries to {BIN_DIR}/ (root:wheel, 755)");
    eprintln!("  • Copy hook dylib to {BIN_DIR}/ (root:wheel, 644)");
    eprintln!("  • Create state directory at {STATE_DIR}/");
    eprintln!("  • Create log directory at {LOG_DIR}/");
    eprintln!("  • Install LaunchDaemon ({PLIST_LABEL})");
    eprintln!("  • Start the daemon");
}

/// Execute the full hardened installation. Must be run as root.
pub fn run_install() -> Result<(), CliError> {
    require_root()?;
    create_service_user()?;
    deploy_binaries()?;
    create_directories()?;
    install_launchdaemon()?;
    start_daemon()?;
    eprintln!("\nstt-guard: initialisation complete.");
    Ok(())
}

fn require_root() -> Result<(), CliError> {
    if !nix_is_root() {
        return Err(CliError::Other(
            "stt-guard init requires root. Run: sudo stt-guard init".into(),
        ));
    }
    Ok(())
}

fn nix_is_root() -> bool {
    unsafe { libc::geteuid() == 0 }
}

fn create_service_user() -> Result<(), CliError> {
    // Check if user already exists.
    let check = Command::new("dscl")
        .args([".", "-read", &format!("/Users/{SERVICE_USER}")])
        .output()
        .map_err(|e| CliError::Other(format!("dscl check: {e}")))?;

    if check.status.success() {
        eprintln!("  {SERVICE_USER} user already exists, skipping creation");
        return Ok(());
    }

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
                "UserShell",
                "/usr/bin/false",
            ],
            "set shell",
        ),
        (
            &[
                ".",
                "-create",
                &format!("/Users/{SERVICE_USER}"),
                "RealName",
                SERVICE_USER_REALNAME,
            ],
            "set realname",
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
        (
            &[
                ".",
                "-create",
                &format!("/Users/{SERVICE_USER}"),
                "NFSHomeDirectory",
                "/var/empty",
            ],
            "set home",
        ),
    ];

    for (args, description) in steps {
        run_cmd("dscl", args, description)?;
    }

    // Create the group with the same GID.
    let group_check = Command::new("dscl")
        .args([".", "-read", &format!("/Groups/{SERVICE_USER}")])
        .output()
        .map_err(|e| CliError::Other(format!("dscl group check: {e}")))?;

    if !group_check.status.success() {
        run_cmd(
            "dscl",
            &[".", "-create", &format!("/Groups/{SERVICE_USER}")],
            "create group",
        )?;
        run_cmd(
            "dscl",
            &[
                ".",
                "-create",
                &format!("/Groups/{SERVICE_USER}"),
                "PrimaryGroupID",
                &uid_str,
            ],
            "set group gid",
        )?;
    }

    Ok(())
}

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

fn source_bin_dir() -> Result<PathBuf, CliError> {
    // The running stt-guard binary's parent directory contains the build artifacts.
    let exe = std::env::current_exe()
        .map_err(|e| CliError::Other(format!("current_exe: {e}")))?;
    exe.parent()
        .map(|p| p.to_path_buf())
        .ok_or_else(|| CliError::Other("cannot determine source binary directory".into()))
}

fn create_directories() -> Result<(), CliError> {
    eprintln!("  Creating state directory at {STATE_DIR}/...");
    std::fs::create_dir_all(STATE_DIR)
        .map_err(|e| CliError::Other(format!("create {STATE_DIR}: {e}")))?;
    run_cmd(
        "chown",
        &[
            &format!("{SERVICE_USER}:{SERVICE_USER}"),
            STATE_DIR,
        ],
        "set state dir ownership",
    )?;
    run_cmd("chmod", &["700", STATE_DIR], "set state dir permissions")?;

    eprintln!("  Creating log directory at {LOG_DIR}/...");
    std::fs::create_dir_all(LOG_DIR)
        .map_err(|e| CliError::Other(format!("create {LOG_DIR}: {e}")))?;
    run_cmd(
        "chown",
        &[&format!("{SERVICE_USER}:{SERVICE_USER}"), LOG_DIR],
        "set log dir ownership",
    )?;
    run_cmd("chmod", &["700", LOG_DIR], "set log dir permissions")?;

    Ok(())
}

fn install_launchdaemon() -> Result<(), CliError> {
    eprintln!("  Installing LaunchDaemon ({PLIST_LABEL})...");

    let plist_content = format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>{PLIST_LABEL}</string>
    <key>ProgramArguments</key>
    <array>
        <string>{BIN_DIR}/stt-guard-daemon</string>
        <string>serve</string>
        <string>--state-dir</string>
        <string>{STATE_DIR}</string>
    </array>
    <key>UserName</key>
    <string>{SERVICE_USER}</string>
    <key>GroupName</key>
    <string>{SERVICE_USER}</string>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardOutPath</key>
    <string>{LOG_DIR}/daemon.out.log</string>
    <key>StandardErrorPath</key>
    <string>{LOG_DIR}/daemon.err.log</string>
</dict>
</plist>
"#
    );

    std::fs::write(PLIST_PATH, plist_content)
        .map_err(|e| CliError::Other(format!("write {PLIST_PATH}: {e}")))?;
    run_cmd(
        "chown",
        &["root:wheel", PLIST_PATH],
        "set plist ownership",
    )?;
    run_cmd("chmod", &["644", PLIST_PATH], "set plist permissions")?;

    Ok(())
}

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

fn run_cmd(program: &str, args: &[&str], description: &str) -> Result<(), CliError> {
    let output = Command::new(program)
        .args(args)
        .output()
        .map_err(|e| CliError::Other(format!("{description}: {e}")))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(CliError::Other(format!(
            "{description} failed: {stderr}"
        )));
    }
    Ok(())
}
