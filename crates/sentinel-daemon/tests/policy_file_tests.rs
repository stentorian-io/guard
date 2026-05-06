use sentinel_daemon::policy_file::{
    find_sentinel_toml, parse_file, sha256_of_file, MAX_DEPTH, PolicyFileError,
};
use std::fs;
use std::path::PathBuf;
use tempfile::TempDir;

fn make_tree(temp: &TempDir, layout: &[(&str, &str)]) -> PathBuf {
    let root = temp.path().to_owned();
    for (rel, content) in layout {
        let p = root.join(rel);
        if let Some(parent) = p.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        if content.is_empty() {
            fs::create_dir_all(&p).unwrap();
        } else {
            fs::write(&p, content).unwrap();
        }
    }
    root
}

#[test]
fn returns_none_when_no_toml_and_no_git() {
    let tmp = TempDir::new().unwrap();
    let root = make_tree(&tmp, &[("a/b/c/.keep", "x")]);
    let r = find_sentinel_toml(&root.join("a/b/c"));
    assert!(
        r.is_none(),
        "expected None when no .sentinel.toml and no .git anywhere; got {r:?}"
    );
}

#[test]
fn finds_toml_in_immediate_parent() {
    let tmp = TempDir::new().unwrap();
    let root = make_tree(
        &tmp,
        &[(".sentinel.toml", "version = 1\n"), ("sub/.keep", "x")],
    );
    let found = find_sentinel_toml(&root.join("sub")).expect("found");
    assert_eq!(
        found,
        root.join(".sentinel.toml").canonicalize().unwrap(),
        "found correct .sentinel.toml"
    );
}

#[test]
fn closest_only_d40() {
    // Both /root/.sentinel.toml and /root/inner/.sentinel.toml exist.
    // Walk-up from /root/inner/sub returns the inner one.
    let tmp = TempDir::new().unwrap();
    let root = make_tree(
        &tmp,
        &[
            (".sentinel.toml", "version = 1\n"),
            ("inner/.sentinel.toml", "version = 1\n"),
            ("inner/sub/.keep", "x"),
        ],
    );
    let found = find_sentinel_toml(&root.join("inner/sub")).expect("found");
    assert_eq!(
        found,
        root.join("inner/.sentinel.toml").canonicalize().unwrap(),
        "D-40 closest-only: inner .sentinel.toml wins"
    );
}

#[test]
fn git_boundary_stops_walk_d36() {
    // /root/.sentinel.toml exists higher up; /root/proj/.git exists.
    // Walk-up from /root/proj/sub stops at .git → returns None.
    let tmp = TempDir::new().unwrap();
    let root = make_tree(
        &tmp,
        &[
            (".sentinel.toml", "version = 1\n"),
            ("proj/.git", ""),
            ("proj/sub/.keep", "x"),
        ],
    );
    let r = find_sentinel_toml(&root.join("proj/sub"));
    assert!(
        r.is_none(),
        "expected None: .git stops walk before reaching the parent .sentinel.toml; got {r:?}"
    );
}

#[test]
fn depth_cap_8_d36() {
    // 12 levels deep; .sentinel.toml at the root.
    let tmp = TempDir::new().unwrap();
    let mut tree: Vec<(&str, &str)> = vec![(".sentinel.toml", "version = 1\n")];
    let levels: Vec<String> = (1..=12).map(|i| format!("d{i}")).collect();
    let deep_path = levels.join("/") + "/.keep";
    tree.push((deep_path.as_str(), "x"));
    let root = make_tree(&tmp, &tree);
    // Build the deep path to walk from.
    let mut start = root.clone();
    for l in &levels {
        start = start.join(l);
    }
    let r = find_sentinel_toml(&start);
    assert!(
        r.is_none(),
        "depth > MAX_DEPTH ({MAX_DEPTH}) must NOT find the toml at the root; got {r:?}"
    );
}

#[test]
fn sha256_of_file_returns_64_char_hex() {
    let tmp = TempDir::new().unwrap();
    let p = tmp.path().join("x");
    fs::write(&p, b"hello").unwrap();
    let h = sha256_of_file(&p).expect("hash");
    assert_eq!(h.len(), 64);
    assert!(h
        .chars()
        .all(|c: char| c.is_ascii_hexdigit() && (c.is_ascii_digit() || c.is_ascii_lowercase())));
    // Known sha256("hello"):
    assert_eq!(
        h,
        "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
    );
}

#[test]
fn parse_file_succeeds_on_valid_toml() {
    let tmp = TempDir::new().unwrap();
    let p = tmp.path().join("ok.toml");
    fs::write(
        &p,
        "version = 1\n[[rules]]\nkind = \"allow\"\nmatch = \"exact\"\npattern = \"x.com\"\nreason = \"why\"\n",
    )
    .unwrap();
    let t = parse_file(&p).expect("parse");
    assert_eq!(t.version, 1);
    assert_eq!(t.rules.len(), 1);
}

#[test]
fn parse_file_returns_unsupported_version_error() {
    let tmp = TempDir::new().unwrap();
    let p = tmp.path().join("bad.toml");
    fs::write(&p, "version = 99\n").unwrap();
    match parse_file(&p) {
        Err(PolicyFileError::UnsupportedVersion(99)) => {}
        other => panic!("expected UnsupportedVersion(99), got {other:?}"),
    }
}

#[test]
fn max_depth_const_is_8() {
    assert_eq!(MAX_DEPTH, 8);
}
