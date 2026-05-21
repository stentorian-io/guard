use guard_daemon::log_writer::rotation::{SIZE_THRESHOLD, rotate, should_rotate};

#[test]
fn should_rotate_at_threshold() {
    let dir = tempfile::tempdir().expect("tempdir");
    let active = dir.path().join("stt-guard.log");
    std::fs::write(&active, b"small").expect("write small");
    assert!(!should_rotate(&active));
    let big = vec![b'x'; (SIZE_THRESHOLD + 1) as usize];
    std::fs::write(&active, &big).expect("write big");
    assert!(should_rotate(&active));
}

#[test]
fn rotate_renames_active_atomically() {
    let dir = tempfile::tempdir().expect("tempdir");
    let active = dir.path().join("stt-guard.log");
    std::fs::write(&active, b"line1\nline2\n").expect("write");
    rotate(&active).expect("rotate");
    assert!(
        !active.exists() || std::fs::metadata(&active).map(|m| m.len()).unwrap_or(0) == 0,
        "active path either absent or empty after rotate"
    );
    // Within 5s, expect a stt-guard-YYYYMMDD-001.log OR .log.gz to exist.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    let mut found = false;
    while std::time::Instant::now() < deadline {
        let count = std::fs::read_dir(dir.path())
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| {
                let n = e.file_name().to_string_lossy().to_string();
                n.starts_with("stt-guard-") && (n.ends_with(".log") || n.ends_with(".log.gz"))
            })
            .count();
        if count >= 1 {
            found = true;
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    assert!(found, "no rotated file appeared within 5s");
}
