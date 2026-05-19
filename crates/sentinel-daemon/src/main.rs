//! sentineld entry — `serve` and `dev-install` subcommands.

use clap::{Parser, Subcommand};
use sentinel_core::Snapshot;
use sentinel_daemon::baseline_staging::BaselineStaging;
use sentinel_daemon::curated::load_curated;
use sentinel_daemon::gap_detector::GapDetector;
use sentinel_daemon::install_artifacts::InstallArtifactStore;
use sentinel_daemon::ipc_server::{DaemonState, IpcServer};
use sentinel_daemon::log_writer::LogWriter;
use sentinel_daemon::manifest;
use sentinel_daemon::prompt::{PromptDedup, RecentGapsRing};
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
}

fn main() -> std::io::Result<()> {
    // Route tracing logs to stderr (tracing-subscriber defaults to stdout;
    // daemon logs must go to stderr so `DaemonHarness::drain_stderr` can
    // capture them in e2e tests, and so launchctl journal captures them
    // correctly for the user-facing `sentinel logs` command).
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::Serve { state_dir } => serve(state_dir.unwrap_or_else(default_state_dir)),
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

    // Initial daemon-startup snapshot — v0.1 path scheme. v0.2 per-run
    // snapshots come via PrepareSnapshot but the startup snapshot is preserved
    // so any pre-v0.2 CLI caller (or post-install smoke probe) still sees
    // a SCHEMA_V2 snapshot at the legacy path. Use v2_default rather than
    // v1_default so the published bytes round-trip Snapshot::decode.
    let nonce: u64 = rand::random();
    let snap = Snapshot::v2_default();
    let pub_ = publish(&state_dir, &snap, nonce)?;
    manifest::write(&state_dir, &pub_)?;
    info!(
        snapshot = %pub_.path.display(),
        digest = %pub_.digest_hex,
        "daemon-startup snapshot published"
    );

    // v0.3: log directory + writer.
    let log_dir = match std::env::var_os("SENTINEL_LOG_DIR") {
        Some(p) => PathBuf::from(p),
        None => {
            let home = std::env::var_os("HOME")
                .map(PathBuf::from)
                .unwrap_or_else(|| PathBuf::from("/tmp"));
            home.join("Library").join("Logs").join("Sentinel")
        }
    };
    std::fs::create_dir_all(&log_dir)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(
            &log_dir,
            std::fs::Permissions::from_mode(0o700),
        );
    }
    let log_writer = LogWriter::spawn(log_dir.join("sentinel.log"))
        .map_err(|e| std::io::Error::other(format!("spawn log_writer: {e}")))?;
    info!(path = %log_dir.join("sentinel.log").display(), "log_writer spawned");

    // v0.3: install_artifacts store opens against the same sentinel.db
    // that RuleStore already migrated above.
    let install_artifact_store = Arc::new(
        InstallArtifactStore::open(&db_path(&state_dir))
            .map_err(|e| std::io::Error::other(format!("open install_artifact_store: {e}")))?,
    );

    // v0.3: prompt + baseline subsystems.
    let prompt_dedup = Arc::new(PromptDedup::new());
    let recent_gaps = Arc::new(RecentGapsRing::new());
    let baseline_staging = Arc::new(BaselineStaging::new());

    let process_tree = Arc::new(ProcessTree::new());
    let gap_detector = Arc::new(GapDetector::new());
    let state = Arc::new(DaemonState {
        process_tree: process_tree.clone(),
        gap_detector,
        rule_store,
        curated,
        state_dir: state_dir.clone(),
        install_artifact_store,
        log_writer,
        prompt_dedup,
        recent_gaps,
        baseline_staging,
        last_snapshot_publish_failed: std::sync::atomic::AtomicBool::new(false),
        deferred_resolve: std::sync::Arc::new(sentinel_daemon::ipc_server::DeferredResolveTable::new()),
        startup_instant: std::time::Instant::now(),
    });

    // Spawn the per-run snapshot GC sweeper (v0.2).
    // The handle is intentionally dropped — the GC thread runs as long as the
    // daemon process; on daemon exit the OS reaps the thread.
    let _gc_handle = sentinel_daemon::snapshot_gc::spawn_gc_thread(
        state_dir.clone(),
        process_tree.clone(),
    );
    info!(interval_secs = sentinel_daemon::snapshot_gc::GC_INTERVAL_SECS, "gc sweeper spawned");

    // Spawn the persistence-path watcher (replaces hook-side open/openat
    // interpose disabled on macOS 26+ due to dyld init-order crashes).
    let _persist_handle = sentinel_daemon::persistence_watcher::spawn_watcher(
        process_tree,
        state.log_writer.clone(),
    );
    info!("persistence watcher spawned");

    // TODO: wire gap_detector -> log_writer + recent_gaps when the gap fires.
    //   - hardened-runtime gap (csops): extends gap_detector closure
    //   - env-not-propagated gap (TREE-06): extends EnvNotPropagatedGap handler
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

    server.run_forever()
}

