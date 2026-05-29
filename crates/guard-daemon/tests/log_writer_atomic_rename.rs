use guard_daemon::log_writer::rotation::rotate;

#[test]
fn rotate_does_not_lose_lines_mid_write() {
    // Pitfall 5 / R-07: rotate must rename atomically; subsequent appends to the new
    // active file (created by the writer post-rename) must not collide with the rotated copy.
    let dir = tempfile::tempdir().expect("tempdir");
    let active = dir.path().join("stt-guard.log");
    std::fs::write(&active, b"line A\nline B\nline C\n").expect("seed");
    rotate(&active).expect("rotate");
    // Writer would now reopen 'active' fresh:
    std::fs::write(&active, b"line D\n").expect("post-rotate write");

    // After rotate, the rotated file (or its .gz form once gzip thread finishes) holds A/B/C.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    let mut found_rotated = false;
    while std::time::Instant::now() < deadline {
        let entries: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .filter_map(std::result::Result::ok)
            .collect();
        for e in &entries {
            let n = e.file_name().to_string_lossy().to_string();
            if n.starts_with("stt-guard-") && n != "stt-guard.log" {
                // Either ".log" or ".log.gz" — both acceptable.
                found_rotated = true;
            }
        }
        if found_rotated {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    assert!(found_rotated, "rotated artifact missing after rename");
    assert!(
        active.exists(),
        "active log missing after post-rotate write"
    );
}
