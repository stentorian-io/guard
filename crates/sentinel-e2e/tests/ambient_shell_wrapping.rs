//! M003-S03: verify ambient shell wrapping.
//!
//! After `sentinel setup`, sourcing init.sh should:
//!   - export SENTINEL_AMBIENT=1
//!   - wrap npm/pip/cargo/etc. so install subcommands run under sentinel
//!   - leave non-install subcommands unwrapped

use std::process::Command;

fn write_init_sh(home: &std::path::Path) -> std::path::PathBuf {
    let config_dir = home.join(".config").join("sentinel");
    std::fs::create_dir_all(&config_dir).unwrap();
    let init_sh = config_dir.join("init.sh");
    // Read init.sh from the installed location or use the canonical body.
    // We build sentinel CLI and run `sentinel setup --target shell` to
    // produce the file, but for test isolation we just write it directly.
    let body = include_str!("../../sentinel-cli/src/install/init_script_body.sh");
    std::fs::write(&init_sh, body).unwrap();
    init_sh
}

fn make_fake_sentinel(home: &std::path::Path) -> std::path::PathBuf {
    let bin_dir = home.join("bin");
    std::fs::create_dir_all(&bin_dir).unwrap();
    let fake_sentinel = bin_dir.join("sentinel");
    std::fs::write(
        &fake_sentinel,
        "#!/bin/sh\necho \"SENTINEL_CALLED: $*\"\n",
    )
    .unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&fake_sentinel, std::fs::Permissions::from_mode(0o755))
            .unwrap();
    }
    bin_dir
}

/// Sourcing init.sh sets SENTINEL_AMBIENT=1.
#[cfg_attr(not(target_os = "macos"), ignore)]
#[test]
fn init_sh_sets_ambient_env() {
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path();
    let init_sh = write_init_sh(home);
    let bin_dir = make_fake_sentinel(home);

    let path = format!(
        "{}:{}",
        bin_dir.display(),
        std::env::var("PATH").unwrap_or_default()
    );

    let output = Command::new("/bin/sh")
        .arg("-c")
        .arg(format!(
            ". '{}' && echo \"AMBIENT=$SENTINEL_AMBIENT\"",
            init_sh.display()
        ))
        .env("HOME", home)
        .env("PATH", &path)
        .output()
        .expect("run shell");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("AMBIENT=1"),
        "SENTINEL_AMBIENT should be set; stdout={stdout}"
    );
}

/// The npm wrapper calls `sentinel run npm install ...` for install subcommands.
#[cfg_attr(not(target_os = "macos"), ignore)]
#[test]
fn npm_install_is_wrapped() {
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path();
    let init_sh = write_init_sh(home);

    // Create a fake sentinel binary that echoes its args
    let bin_dir = home.join("bin");
    std::fs::create_dir_all(&bin_dir).unwrap();
    let fake_sentinel = bin_dir.join("sentinel");
    std::fs::write(
        &fake_sentinel,
        "#!/bin/sh\necho \"SENTINEL_CALLED: $*\"\n",
    )
    .unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&fake_sentinel, std::fs::Permissions::from_mode(0o755))
            .unwrap();
    }

    let path = format!(
        "{}:{}",
        bin_dir.display(),
        std::env::var("PATH").unwrap_or_default()
    );

    let output = Command::new("/bin/sh")
        .arg("-c")
        .arg(format!(
            ". '{}' && npm install left-pad",
            init_sh.display()
        ))
        .env("HOME", home)
        .env("PATH", &path)
        .output()
        .expect("run shell with npm install");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("SENTINEL_CALLED: run npm install left-pad"),
        "npm install should be wrapped; stdout={stdout}"
    );
}

/// Non-install npm subcommands (e.g. `npm list`) should NOT go through sentinel.
#[cfg_attr(not(target_os = "macos"), ignore)]
#[test]
fn npm_list_not_wrapped() {
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path();
    let init_sh = write_init_sh(home);

    // Create a fake sentinel binary
    let bin_dir = home.join("bin");
    std::fs::create_dir_all(&bin_dir).unwrap();
    let fake_sentinel = bin_dir.join("sentinel");
    std::fs::write(
        &fake_sentinel,
        "#!/bin/sh\necho \"SENTINEL_CALLED: $*\"\n",
    )
    .unwrap();
    // Create a fake npm binary
    let fake_npm = bin_dir.join("npm");
    std::fs::write(&fake_npm, "#!/bin/sh\necho \"NPM_DIRECT: $*\"\n").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&fake_sentinel, std::fs::Permissions::from_mode(0o755))
            .unwrap();
        std::fs::set_permissions(&fake_npm, std::fs::Permissions::from_mode(0o755))
            .unwrap();
    }

    let path = format!(
        "{}:{}",
        bin_dir.display(),
        std::env::var("PATH").unwrap_or_default()
    );

    let output = Command::new("/bin/sh")
        .arg("-c")
        .arg(format!(". '{}' && npm list", init_sh.display()))
        .env("HOME", home)
        .env("PATH", &path)
        .output()
        .expect("run shell with npm list");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("NPM_DIRECT: list"),
        "npm list should NOT be wrapped; stdout={stdout}"
    );
    assert!(
        !stdout.contains("SENTINEL_CALLED"),
        "sentinel should NOT be called for npm list; stdout={stdout}"
    );
}
