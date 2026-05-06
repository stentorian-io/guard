use sentinel_cli::install::marker_block::{install, strip, BEGIN_MARKER, END_MARKER};

#[test]
fn install_inserts_block_in_clean_file() {
    let dir = tempfile::tempdir().expect("tempdir");
    let rc = dir.path().join(".zshrc");
    std::fs::write(&rc, "alias ll='ls -la'\n").expect("seed");
    install(&rc).expect("install");
    let body = std::fs::read_to_string(&rc).expect("read");
    assert!(body.contains(BEGIN_MARKER));
    assert!(body.contains(END_MARKER));
    assert!(body.starts_with("alias ll="));
}

#[test]
fn install_idempotent_no_double_block() {
    let dir = tempfile::tempdir().expect("tempdir");
    let rc = dir.path().join(".zshrc");
    std::fs::write(&rc, "alias ll='ls -la'\n").expect("seed");
    install(&rc).expect("first");
    install(&rc).expect("second");
    let body = std::fs::read_to_string(&rc).expect("read");
    let begin_count = body.matches(BEGIN_MARKER).count();
    assert_eq!(begin_count, 1, "expected exactly one marker block; got {begin_count}");
}

#[test]
fn strip_removes_block_idempotently() {
    let dir = tempfile::tempdir().expect("tempdir");
    let rc = dir.path().join(".zshrc");
    std::fs::write(&rc, "alias ll='ls'\n").expect("seed");
    install(&rc).expect("install");
    strip(&rc).expect("strip");
    let body = std::fs::read_to_string(&rc).expect("read");
    assert!(!body.contains(BEGIN_MARKER));
    // strip again is no-op:
    strip(&rc).expect("strip again");
    assert_eq!(std::fs::read_to_string(&rc).unwrap(), body);
}

#[test]
fn install_through_symlink_writes_to_target() {
    let dir = tempfile::tempdir().expect("tempdir");
    let real = dir.path().join("real_zshrc");
    let link = dir.path().join(".zshrc");
    std::fs::write(&real, "alias ll='ls'\n").expect("seed");
    std::os::unix::fs::symlink(&real, &link).expect("symlink");
    install(&link).expect("install");
    // The symlink itself must remain a symlink (R-04 — chezmoi/dotfile-managed setup).
    let meta = std::fs::symlink_metadata(&link).expect("metadata");
    assert!(meta.file_type().is_symlink(), "symlink replaced with regular file (R-04 fail)");
    // The TARGET file holds the marker.
    let target_body = std::fs::read_to_string(&real).expect("read");
    assert!(target_body.contains(BEGIN_MARKER));
}
