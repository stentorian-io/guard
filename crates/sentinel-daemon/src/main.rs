//! sentineld entry — `serve` and `dev-install` subcommands.

use clap::{Parser, Subcommand};
use sentinel_core::Snapshot;
use sentinel_daemon::dev_install;
use sentinel_daemon::ipc_server::IpcServer;
use sentinel_daemon::manifest;
use sentinel_daemon::snapshot::publish;
use sentinel_daemon::state_dir::{default_state_dir, ensure_state_dir, ready_path, socket_path};
use sentinel_daemon::tracked::TrackedRoots;
use std::path::PathBuf;
use std::sync::Arc;
use tracing::info;

#[derive(Parser)]
#[command(name = "sentineld", about = "Sentinel user-level daemon")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Run the daemon: publish snapshot, bind socket, accept RegisterRoot.
    Serve {
        #[arg(long)]
        state_dir: Option<PathBuf>,
    },
    /// Write the LaunchAgent plist and launchctl bootstrap it.
    DevInstall {
        #[arg(long)]
        state_dir: Option<PathBuf>,
        #[arg(long)]
        skip_bootstrap: bool,
    },
}

fn main() -> std::io::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::Serve { state_dir } => serve(state_dir.unwrap_or_else(default_state_dir)),
        Cmd::DevInstall {
            state_dir,
            skip_bootstrap,
        } => dev_install_run(state_dir.unwrap_or_else(default_state_dir), skip_bootstrap),
    }
}

fn serve(state_dir: PathBuf) -> std::io::Result<()> {
    ensure_state_dir(&state_dir)?;
    let nonce: u64 = rand::random();
    let snap = Snapshot::phase1_default();
    let pub_ = publish(&state_dir, &snap, nonce)?;
    manifest::write(&state_dir, &pub_)?;
    info!(
        snapshot = %pub_.path.display(),
        digest = %pub_.digest_hex,
        "snapshot published"
    );

    let tracked = Arc::new(TrackedRoots::new());
    let server = IpcServer::bind(&socket_path(&state_dir), tracked.clone())?;
    let pid = unsafe { libc::getpid() };
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    std::fs::write(ready_path(&state_dir), format!("{pid} {now}\n"))?;
    info!(
        socket = %socket_path(&state_dir).display(),
        "daemon ready"
    );
    server.run_forever()
}

fn dev_install_run(state_dir: PathBuf, skip_bootstrap: bool) -> std::io::Result<()> {
    let exe = std::env::current_exe()?;
    let plist = dev_install::write(&exe, &state_dir)?;
    info!(plist = %plist.display(), "wrote LaunchAgent plist");
    if !skip_bootstrap {
        dev_install::launchctl_bootstrap(&plist)?;
        info!("launchctl bootstrap succeeded");
    } else {
        info!(
            "--skip-bootstrap given; user must run `launchctl bootstrap gui/$UID {}` manually",
            plist.display()
        );
    }
    Ok(())
}
