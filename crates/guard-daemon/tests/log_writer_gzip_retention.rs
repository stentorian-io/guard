use guard_daemon::log_writer::rotation::{MAX_ARCHIVES, MAX_TOTAL_BYTES, enforce_retention};

fn touch(path: &std::path::Path, size: usize) {
    std::fs::write(path, vec![0u8; size]).expect("write");
}

#[test]
fn retention_count_keeps_newest_seven() {
    let dir = tempfile::tempdir().expect("tempdir");
    for i in 0..10 {
        let p = dir
            .path()
            .join(format!("stt-guard-20260101-{:03}.log.gz", i));
        touch(&p, 10);
        // Stagger mtimes by setting them via filetime-equivalent — simplest: sleep briefly.
        std::thread::sleep(std::time::Duration::from_millis(15));
    }
    enforce_retention(dir.path()).expect("retention");
    let remaining: Vec<_> = std::fs::read_dir(dir.path())
        .unwrap()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_name().to_string_lossy().ends_with(".log.gz"))
        .collect();
    assert_eq!(remaining.len(), MAX_ARCHIVES);
    // The 7 newest are 003..009.
    let names: Vec<_> = remaining
        .iter()
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .collect();
    assert!(names.iter().any(|n| n.contains("009")));
    assert!(!names.iter().any(|n| n.contains("000")));
}

#[test]
fn retention_size_cap_evicts_oldest() {
    let dir = tempfile::tempdir().expect("tempdir");
    // 6 archives, each 50 MiB (well under count cap, but 300 MiB total > 256 MiB cap).
    let big = 50 * 1024 * 1024;
    for i in 0..6 {
        let p = dir
            .path()
            .join(format!("stt-guard-20260102-{:03}.log.gz", i));
        touch(&p, big);
        std::thread::sleep(std::time::Duration::from_millis(15));
    }
    enforce_retention(dir.path()).expect("retention");
    let remaining: u64 = std::fs::read_dir(dir.path())
        .unwrap()
        .filter_map(|e| e.ok())
        .map(|e| e.metadata().map(|m| m.len()).unwrap_or(0))
        .sum();
    assert!(
        remaining <= MAX_TOTAL_BYTES,
        "remaining {remaining} > cap {MAX_TOTAL_BYTES}"
    );
}
