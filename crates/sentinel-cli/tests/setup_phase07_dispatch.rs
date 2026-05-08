//! Phase 07 plan 03 task 3 — RED test pinning the new `setup::run_setup`
//! dispatch surface and its mutual-exclusion check on `--remove` /
//! `--reinstall`.

use sentinel_cli::setup;
use sentinel_cli::uninstall::SetupTarget;
use sentinel_cli::CliError;
use std::path::Path;

#[test]
fn run_setup_signature_pinned() {
    let _: fn(
        &Path,
        &Path,
        Option<SetupTarget>,
        bool,
        bool,
        bool,
    ) -> Result<i32, CliError> = setup::run_setup;
}

#[test]
fn run_setup_rejects_remove_and_reinstall_together() {
    // Mutual exclusion: --remove + --reinstall is a hard error
    // (RESEARCH.md Open Question #1, option a).
    let tmp = tempfile::tempdir().unwrap();
    let sock = tmp.path().join("sentinel.sock");
    let state_dir = tmp.path().join("state");
    let result = setup::run_setup(
        &sock,
        &state_dir,
        /*target=*/ None,
        /*remove=*/ true,
        /*reinstall=*/ true,
        /*yes=*/ true,
    );
    match result {
        Err(CliError::Other(msg)) => {
            assert!(
                msg.contains("--remove and --reinstall are mutually exclusive"),
                "expected mutual-exclusion error, got: {msg}"
            );
        }
        other => panic!(
            "expected CliError::Other(mutual-exclusion), got: {other:?}"
        ),
    }
}
