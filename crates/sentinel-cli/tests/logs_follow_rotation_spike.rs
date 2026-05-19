//! v0.3 spike: verifies notify 8.2 detects file rename events on macOS
//! within 2 seconds.

use std::path::PathBuf;
use std::sync::mpsc::channel;
use std::time::Duration;
use notify::{EventKind, RecursiveMode, Watcher, event::ModifyKind, recommended_watcher};

#[test]
fn rename_event_observable_within_2s() {
    let dir = tempfile::tempdir().expect("tempdir");
    let active: PathBuf = dir.path().join("sentinel.log");
    std::fs::write(&active, b"line1\n").expect("seed");

    let (tx, rx) = channel();
    let mut watcher = recommended_watcher(tx).expect("watcher");
    watcher
        .watch(&active, RecursiveMode::NonRecursive)
        .expect("watch");

    // Trigger a rotation by renaming.
    let rotated = dir.path().join("sentinel-20260506-001.log");
    std::fs::rename(&active, &rotated).expect("rename");
    // Recreate the active file (simulates writer reopening post-rotate).
    std::fs::write(&active, b"line2\n").expect("recreate");

    // Wait up to 2s for at least one Name modify event.
    let deadline = std::time::Instant::now() + Duration::from_secs(2);
    let mut saw_rename = false;
    while std::time::Instant::now() < deadline {
        match rx.recv_timeout(Duration::from_millis(200)) {
            Ok(Ok(ev)) => {
                if matches!(ev.kind, EventKind::Modify(ModifyKind::Name(_))) {
                    saw_rename = true;
                    break;
                }
            }
            Ok(Err(_)) | Err(_) => continue,
        }
    }
    assert!(saw_rename, "notify did not emit a rename event within 2s; A2 unverified");
}
