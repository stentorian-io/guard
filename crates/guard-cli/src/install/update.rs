//! Self-managed release update flow.
//!
//! Updates intentionally reuse the release artifact and checksum model used by
//! `install.sh`: fetch the selected GitHub Release tarball, verify it with the
//! release checksum file, then run the downloaded CLI's privileged system
//! installer. The running binary never rewrites itself.

use std::ffi::OsStr;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::CliError;

const GITHUB_API_LATEST_RELEASE: &str =
    "https://api.github.com/repos/stentorian-io/guard/releases/latest";
const GITHUB_RELEASE_BASE: &str = "https://github.com/stentorian-io/guard/releases/download";

/// Check for or apply a release update.
///
/// # Errors
///
/// Returns an error when release lookup, download, checksum verification,
/// extraction, or installer execution fails.
pub fn run_update(check: bool, version: Option<String>) -> Result<i32, CliError> {
    let target = release_target()?;
    let selected_release = selected_release(version)?;
    let selected_version = selected_release.trim_start_matches('v');
    let current_version = env!("CARGO_PKG_VERSION");

    if check {
        if selected_version == current_version {
            println!("stt-guard is up to date ({current_version}).");
        } else {
            println!("stt-guard update available: {selected_release}");
            println!("installed: v{current_version}");
            println!("run: stt-guard update");
        }

        return Ok(0);
    }

    if selected_version == current_version {
        println!("stt-guard is already up to date ({current_version}).");
        return Ok(0);
    }

    let asset = format!("guard-{selected_version}-{target}.tar.gz");
    let release_url = format!("{GITHUB_RELEASE_BASE}/{selected_release}");
    let workspace = TempWorkspace::create()?;
    let tarball_path = workspace.path().join(&asset);
    let checksums_path = workspace.path().join("checksums.txt");

    eprintln!("stt-guard: downloading {asset}");
    download_to(&format!("{release_url}/{asset}"), &tarball_path)?;
    download_to(&format!("{release_url}/checksums.txt"), &checksums_path)?;

    let expected_sha = expected_sha256(&checksums_path, &asset)?;
    let actual_sha = sha256_file(&tarball_path)?;
    if actual_sha != expected_sha {
        return Err(CliError::Other(format!(
            "checksum mismatch for {asset}: expected {expected_sha}, got {actual_sha}"
        )));
    }

    extract_tarball(&tarball_path, workspace.path())?;
    run_downloaded_system_installer(&workspace.path().join("stt-guard"))?;

    println!("stt-guard: updated to {selected_release}");
    Ok(0)
}

fn selected_release(version: Option<String>) -> Result<String, CliError> {
    let version = match version {
        Some(version) => version,
        None => latest_release_tag()?,
    };

    if version.trim().is_empty() {
        return Err(CliError::Other("release version is empty".into()));
    }

    if version.starts_with('v') {
        Ok(version)
    } else {
        Ok(format!("v{version}"))
    }
}

fn latest_release_tag() -> Result<String, CliError> {
    let output = run_capture("curl", ["-fsSL", GITHUB_API_LATEST_RELEASE])?;
    let json: serde_json::Value = serde_json::from_slice(&output)
        .map_err(|e| CliError::Other(format!("parse latest release metadata: {e}")))?;

    json.get("tag_name")
        .and_then(serde_json::Value::as_str)
        .map(ToOwned::to_owned)
        .ok_or_else(|| CliError::Other("latest release metadata did not include tag_name".into()))
}

fn release_target() -> Result<&'static str, CliError> {
    let os = run_capture("uname", ["-s"])?;
    let arch = run_capture("uname", ["-m"])?;
    let os = String::from_utf8_lossy(&os);
    let arch = String::from_utf8_lossy(&arch);

    match (os.trim(), arch.trim()) {
        ("Darwin", "arm64") => Ok("aarch64-apple-darwin"),
        ("Darwin", "x86_64") => Ok("x86_64-apple-darwin"),
        ("Darwin", other) => Err(CliError::Other(format!(
            "unsupported macOS architecture: {other}"
        ))),
        (other, _) => Err(CliError::Other(format!(
            "self-managed updates are currently supported on macOS only, got {other}"
        ))),
    }
}

fn download_to(url: &str, destination: &Path) -> Result<(), CliError> {
    run_status(
        "curl",
        [
            OsStr::new("-fsSL"),
            OsStr::new("-o"),
            destination.as_os_str(),
            OsStr::new(url),
        ],
        &format!("download {url}"),
    )
}

fn expected_sha256(checksums_path: &Path, asset: &str) -> Result<String, CliError> {
    let checksums = std::fs::read_to_string(checksums_path)
        .map_err(|e| CliError::Other(format!("read {}: {e}", checksums_path.display())))?;

    for line in checksums.lines() {
        let mut fields = line.split_whitespace();
        let Some(sha) = fields.next() else {
            continue;
        };
        let Some(name) = fields.next() else {
            continue;
        };

        if name == asset {
            return Ok(sha.to_string());
        }
    }

    Err(CliError::Other(format!("no checksum found for {asset}")))
}

fn sha256_file(path: &Path) -> Result<String, CliError> {
    let output = Command::new("shasum")
        .args(["-a", "256"])
        .arg(path)
        .output()
        .map_err(|e| CliError::Other(format!("run shasum: {e}")))?;

    if !output.status.success() {
        return Err(CliError::Other(format!(
            "shasum failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let sha = stdout
        .split_whitespace()
        .next()
        .ok_or_else(|| CliError::Other("shasum did not print a digest".into()))?;

    Ok(sha.to_string())
}

fn extract_tarball(tarball_path: &Path, destination: &Path) -> Result<(), CliError> {
    run_status(
        "tar",
        [
            OsStr::new("-xzf"),
            tarball_path.as_os_str(),
            OsStr::new("-C"),
            destination.as_os_str(),
        ],
        &format!("extract {}", tarball_path.display()),
    )
}

fn run_downloaded_system_installer(cli_path: &Path) -> Result<(), CliError> {
    if !cli_path.exists() {
        return Err(CliError::Other(format!(
            "release artifact did not contain {}",
            cli_path.display()
        )));
    }

    run_status(
        "sudo",
        [
            cli_path.as_os_str(),
            OsStr::new("install-system"),
            OsStr::new("--yes"),
        ],
        "run system installer",
    )
}

fn run_capture<I, S>(program: &str, args: I) -> Result<Vec<u8>, CliError>
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    let output = Command::new(program)
        .args(args)
        .output()
        .map_err(|e| CliError::Other(format!("run {program}: {e}")))?;

    if !output.status.success() {
        return Err(CliError::Other(format!(
            "{program} failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }

    Ok(output.stdout)
}

fn run_status<I, S>(program: &str, args: I, description: &str) -> Result<(), CliError>
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    let status = Command::new(program)
        .args(args)
        .status()
        .map_err(|e| CliError::Other(format!("{description}: {e}")))?;

    if !status.success() {
        return Err(CliError::Other(format!(
            "{description} failed with status {status}"
        )));
    }

    Ok(())
}

struct TempWorkspace {
    path: PathBuf,
}

impl TempWorkspace {
    fn create() -> Result<Self, CliError> {
        let mut path = std::env::temp_dir();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| CliError::Other(format!("system clock before unix epoch: {e}")))?;
        path.push(format!(
            "stt-guard-update.{}.{}",
            std::process::id(),
            now.as_nanos()
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

impl Drop for TempWorkspace {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}
