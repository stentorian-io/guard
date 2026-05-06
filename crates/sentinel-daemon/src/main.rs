//! sentineld entry — `serve` and `dev-install` subcommands.

use clap::{Parser, Subcommand};
use sentinel_core::Snapshot;
use sentinel_daemon::curated::load_curated;
use sentinel_daemon::dev_install;
use sentinel_daemon::gap_detector::GapDetector;
use sentinel_daemon::ipc_server::{DaemonState, IpcServer};
use sentinel_daemon::manifest;
use sentinel_daemon::rule_store::RuleStore;
use sentinel_daemon::snapshot::publish;
use sentinel_daemon::state_dir::{
    db_path, default_state_dir, ensure_runs_dir, ensure_state_dir, ready_path, socket_path,
};
use sentinel_daemon::tracked::ProcessTree;
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
    ensure_runs_dir(&state_dir)?;

    // Load curated YAML once at startup. PrepareSnapshot reuses this slice on
    // every per-run snapshot publish; no repeated parse cost.
    let curated =
        load_curated().map_err(|e| std::io::Error::other(format!("load curated yaml: {e}")))?;
    let curated = Arc::new(curated);

    // Open the SQLite rule store (creates if missing; runs migrations).
    let rule_store = RuleStore::open(&db_path(&state_dir))
        .map_err(|e| std::io::Error::other(format!("open rule_store: {e}")))?;
    let rule_store = Arc::new(rule_store);

    // Initial daemon-startup snapshot — Phase 1 path scheme. Phase 2 per-run
    // snapshots come via PrepareSnapshot but the startup snapshot is preserved
    // so any pre-Phase-2-CLI caller (or post-install smoke probe) still sees
    // a SCHEMA_V2 snapshot at the legacy path. Use phase2_default rather than
    // phase1_default so the published bytes round-trip Snapshot::decode.
    let nonce: u64 = rand::random();
    let snap = Snapshot::phase2_default();
    let pub_ = publish(&state_dir, &snap, nonce)?;
    manifest::write(&state_dir, &pub_)?;
    info!(
        snapshot = %pub_.path.display(),
        digest = %pub_.digest_hex,
        "daemon-startup snapshot published"
    );

    let process_tree = Arc::new(ProcessTree::new());
    let gap_detector = Arc::new(GapDetector::new());
    let state = Arc::new(DaemonState::new(
        process_tree.clone(),
        gap_detector,
        rule_store,
        curated,
        state_dir.clone(),
    ));
    let server = IpcServer::bind(&socket_path(&state_dir), state)?;
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

    // Spawn the per-run snapshot GC sweeper (D-29 / plan 02-07).
    // The handle is intentionally dropped — the GC thread runs as long as the
    // daemon process; on daemon exit the OS reaps the thread.
    let _gc_handle = sentinel_daemon::snapshot_gc::spawn_gc_thread(
        state_dir.clone(),
        process_tree,
    );
    info!(interval_secs = sentinel_daemon::snapshot_gc::GC_INTERVAL_SECS, "gc sweeper spawned");

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
