//! Spike A1: validate gix 0.83 shallow-clone API call sequence.
//!
//! Resolves Open Question 1 (RESEARCH.md Tertiary Sources line 977 — LOW
//! confidence on the exact gix 0.83 PrepareFetch chain).
//!
//! Constraints:
//! - HERMETIC: file:// fixture repo only — no network access.
//! - <10s wall-clock on Apple Silicon laptop.
//! - The system `git` CLI is used ONLY to construct the fixture repo (init +
//!   add + commit). The operation under test (clone-then-fetch) uses gix.
//!   Rationale: gix's init/commit APIs are awkward for fixture construction
//!   and exercising them is not the spike's purpose; the spike validates the
//!   PrepareFetch + Shallow + main_worktree chain that plan 02 will use.
//!
//! Plan 02's `feed/fetcher.rs` should copy the API call shape captured in
//! the `// SPIKE-API-VERIFIED:` comments below — those are the exact lines
//! that compiled against gix 0.83 in this project.
//!
//! NOTE on shallow over file:// transport: gix may not honor
//! `Shallow::DepthAtRemote(1)` over the file protocol the same way it does
//! over HTTPS smart-protocol. The spike still drives `with_shallow(...)` so
//! the API surface is exercised; the resulting working tree is the relevant
//! check (working tree contains the fixture file).

use std::num::NonZeroU32;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::AtomicBool;

use tempfile::TempDir;

/// Build a tiny git repo at `path` with a single committed file.
///
/// Returns the commit SHA. Uses the system `git` CLI for fixture setup only
/// (see module-level note).
fn build_fixture_repo(path: &Path) -> String {
    fn git(dir: &Path, args: &[&str]) -> std::process::Output {
        let out = Command::new("git")
            .args(args)
            .current_dir(dir)
            // Force deterministic identity for reproducible commits.
            .env("GIT_AUTHOR_NAME", "spike")
            .env("GIT_AUTHOR_EMAIL", "spike@example.invalid")
            .env("GIT_COMMITTER_NAME", "spike")
            .env("GIT_COMMITTER_EMAIL", "spike@example.invalid")
            .env("GIT_AUTHOR_DATE", "2026-01-01T00:00:00Z")
            .env("GIT_COMMITTER_DATE", "2026-01-01T00:00:00Z")
            .output()
            .expect("git invocation failed");
        if !out.status.success() {
            panic!(
                "git {:?} failed in {:?}: {}",
                args,
                dir,
                String::from_utf8_lossy(&out.stderr)
            );
        }
        out
    }

    std::fs::create_dir_all(path).expect("mkdir");
    git(path, &["init", "-q", "-b", "main"]);
    let osv_dir = path.join("osv");
    std::fs::create_dir_all(&osv_dir).expect("mkdir osv/");
    let fixture_json = r#"{
  "schema_version": "1.7.4",
  "id": "MAL-2026-FIXTURE",
  "modified": "2026-01-01T00:00:00Z",
  "published": "2026-01-01T00:00:00Z",
  "affected": [{"package": {"ecosystem": "npm", "name": "fixture-pkg"}, "versions": ["1.0.0"]}]
}
"#;
    std::fs::write(osv_dir.join("MAL-2026-FIXTURE.json"), fixture_json).expect("write fixture");
    git(path, &["add", "."]);
    git(path, &["commit", "-q", "-m", "fixture"]);
    let sha = git(path, &["rev-parse", "HEAD"]);
    String::from_utf8_lossy(&sha.stdout).trim().to_string()
}

/// Build a `file://` URL pointing at `repo_path`.
fn file_url(repo_path: &Path) -> String {
    let canon = repo_path.canonicalize().expect("canonicalize");
    format!("file://{}", canon.display())
}

/// Test 1 — first-time clone: PrepareFetch + Shallow + fetch_then_checkout +
/// main_worktree. This is the "no .git/ directory yet" path.
#[test]
fn spike_first_clone_then_iterate_files() {
    let fixture_dir = TempDir::new().expect("tempdir");
    let fixture_repo = fixture_dir.path().join("fixture-repo");
    let fixture_sha = build_fixture_repo(&fixture_repo);
    let url = file_url(&fixture_repo);

    let clone_dir = TempDir::new().expect("tempdir for clone");
    // gix requires the destination to be either non-existent or empty; pick a
    // sub-path that does not exist yet.
    let local: PathBuf = clone_dir.path().join("clone");

    let interrupt = AtomicBool::new(false);

    // SPIKE-API-VERIFIED: gix 0.83 first-time-clone call chain.
    // 1. PrepareFetch::new(url, path, Kind::WithWorktree, defaults, defaults)
    // 2. .with_shallow(Shallow::DepthAtRemote(NonZeroU32::new(1)?))
    // 3. .fetch_then_checkout(progress::Discard, &AtomicBool) -> (PrepareCheckout, Outcome)
    // 4. PrepareCheckout::main_worktree(progress::Discard, &AtomicBool) -> (Repository, Outcome)
    let mut prepare = gix::clone::PrepareFetch::new(
        url.as_str(),
        &local,
        gix::create::Kind::WithWorktree,
        gix::create::Options::default(),
        gix::open::Options::default(),
    )
    .expect("PrepareFetch::new")
    .with_shallow(gix::remote::fetch::Shallow::DepthAtRemote(
        NonZeroU32::new(1).expect("nonzero"),
    ));

    let (mut checkout, _fetch_outcome) = prepare
        .fetch_then_checkout(gix::progress::Discard, &interrupt)
        .expect("fetch_then_checkout");

    let (repo, _checkout_outcome) = checkout
        .main_worktree(gix::progress::Discard, &interrupt)
        .expect("main_worktree");

    // Walk the working tree under osv/ and assert the fixture file is present.
    let workdir = repo.workdir().expect("non-bare repo has workdir");
    let mut found = Vec::new();
    for entry in walkdir::WalkDir::new(workdir.join("osv"))
        .into_iter()
        .filter_map(|r| r.ok())
    {
        if entry.file_type().is_file()
            && entry.path().extension().and_then(|s| s.to_str()) == Some("json")
        {
            found.push(entry.path().to_path_buf());
        }
    }
    assert_eq!(
        found.len(),
        1,
        "expected exactly one OSV fixture file under cloned osv/, found {found:?}"
    );

    let body = std::fs::read_to_string(&found[0]).expect("read fixture");
    assert!(
        body.contains("MAL-2026-FIXTURE"),
        "cloned fixture file content roundtrip"
    );

    // The fixture commit SHA exists in the cloned repo's object database (we
    // shallow-fetched the tip, which IS that commit).
    let mut head = repo.head().expect("HEAD");
    let head_id = head
        .try_peel_to_id()
        .expect("peel HEAD")
        .expect("HEAD points at object");
    assert_eq!(
        head_id.to_hex().to_string(),
        fixture_sha,
        "cloned HEAD must equal fixture commit"
    );
}

/// Test 2 — second-run incremental fetch: open existing repo + drive the
/// remote-connect + prepare_fetch + receive chain.
#[test]
fn spike_second_run_fetch_uses_existing() {
    // First, run the first-clone path to land an on-disk repo we can re-open.
    let fixture_dir = TempDir::new().expect("tempdir");
    let fixture_repo = fixture_dir.path().join("fixture-repo");
    let _fixture_sha = build_fixture_repo(&fixture_repo);
    let url = file_url(&fixture_repo);

    let clone_dir = TempDir::new().expect("tempdir for clone");
    let local: PathBuf = clone_dir.path().join("clone");

    {
        let interrupt = AtomicBool::new(false);
        let mut prepare = gix::clone::PrepareFetch::new(
            url.as_str(),
            &local,
            gix::create::Kind::WithWorktree,
            gix::create::Options::default(),
            gix::open::Options::default(),
        )
        .expect("PrepareFetch::new")
        .with_shallow(gix::remote::fetch::Shallow::DepthAtRemote(
            NonZeroU32::new(1).expect("nonzero"),
        ));
        let (mut checkout, _) = prepare
            .fetch_then_checkout(gix::progress::Discard, &interrupt)
            .expect("first-run fetch_then_checkout");
        let (_repo, _) = checkout
            .main_worktree(gix::progress::Discard, &interrupt)
            .expect("main_worktree");
    }

    // Now exercise the incremental-fetch path against the same fixture (no
    // new commit; just verify the call chain compiles + returns Ok).
    let interrupt = AtomicBool::new(false);

    // SPIKE-API-VERIFIED: gix 0.83 incremental-fetch call chain.
    // 1. gix::open(local) -> Repository
    // 2. repo.find_remote("origin") -> Remote
    // 3. remote.connect(remote::Direction::Fetch) -> Connection
    // 4. connection.prepare_fetch(&mut Discard, ref_map::Options::default()) -> Prepare
    // 5. prepared.with_shallow(Shallow::DepthAtRemote(1)).receive(&mut Discard, &AtomicBool)
    let repo = gix::open(&local).expect("gix::open");
    let remote = repo.find_remote("origin").expect("find_remote origin");
    let connection = remote
        .connect(gix::remote::Direction::Fetch)
        .expect("remote.connect");

    let mut progress = gix::progress::Discard;
    let prepared = connection
        .prepare_fetch(&mut progress, gix::remote::ref_map::Options::default())
        .expect("connection.prepare_fetch");

    let outcome = prepared
        .with_shallow(gix::remote::fetch::Shallow::DepthAtRemote(
            NonZeroU32::new(1).expect("nonzero"),
        ))
        .receive(&mut progress, &interrupt)
        .expect("prepared.receive");

    // The fetch should land Ok; we don't assert on outcome shape here — the
    // point is that the call chain compiles and runs to completion against a
    // file:// fixture.
    let _ = outcome;
}
