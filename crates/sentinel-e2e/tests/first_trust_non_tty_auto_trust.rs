//! crates/sentinel-e2e/tests/first_trust_non_tty_auto_trust.rs
//!
//! Phase 07 plan 05 — CLI-21 + D-25: untrusted .sentinel.toml in a non-TTY
//! context auto-trusts and emits a stderr notice of the form:
//!   "sentinel: trusted .sentinel.toml at <path> (sha256=<12 hex>; non-TTY auto-trust)"
//!
//! This is end-to-end coverage of the run_orchestrator first-trust block
//! (Plan 04 inserted the prompt + auto-trust path between probe_daemon_alive
//! and prepare_snapshot_v3). It requires a live daemon for the IsTrusted
//! and TrustPolicy IPCs, so it follows the same `#[ignore]` convention as
//! the other DaemonHarness-based e2e tests in this crate (opt-in via
//! `cargo test -p sentinel-e2e -- --ignored first_trust`).

use std::process::{Command, Stdio};

use sentinel_e2e::{resolve_cli, resolve_dylib, DaemonHarness};

#[cfg(target_os = "macos")]
#[test]
#[ignore = "requires DaemonHarness (live sentineld) — opt-in via --ignored"]
fn first_trust_non_tty_emits_auto_trust_notice() {
    let harness = DaemonHarness::start().expect("start daemon harness");
    let cli = resolve_cli();
    let dylib = resolve_dylib();

    let workdir = harness.home.path().join("project");
    std::fs::create_dir_all(&workdir).expect("mkdir project");

    // Write an untrusted .sentinel.toml into the workdir.
    let toml_body = "version = 1\n\n\
                     [[rules]]\n\
                     kind = \"allow\"\n\
                     match = \"exact\"\n\
                     pattern = \"api.example.com\"\n\
                     reason = \"test fixture for first-trust auto-trust\"\n";
    std::fs::write(workdir.join(".sentinel.toml"), toml_body).expect("write .sentinel.toml");

    // Now wrap a quick command from inside workdir with stdin redirected to
    // /dev/null. The first-trust block fires (toml exists + not yet trusted),
    // sees non-TTY stdin, and takes the auto-trust path — emitting the D-25
    // stderr notice before continuing into prepare_snapshot_v3.
    let output = Command::new(&cli)
        .arg("wrap")
        .arg("/bin/echo").arg("hi")
        .env_clear()
        .env("HOME", harness.home.path())
        .env("PATH", std::env::var_os("PATH").unwrap_or_default())
        .env("SENTINEL_HOOK_DYLIB", &dylib)
        .env("SENTINEL_STATE_DIR", &harness.state_dir)
        .current_dir(&workdir)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("spawn sentinel /bin/echo hi");

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("sentinel: trusted .sentinel.toml at"),
        "expected D-25 auto-trust notice; got stderr: {stderr:?}",
    );
    assert!(
        stderr.contains("non-TTY auto-trust"),
        "expected 'non-TTY auto-trust' marker; got stderr: {stderr:?}",
    );

    // sha256= must be followed by 12 lowercase hex chars (per
    // run_orchestrator.rs format string `&sha[..12]`). Use a char-walk
    // rather than introducing a new regex dep.
    let after = stderr
        .split("sha256=")
        .nth(1)
        .unwrap_or_else(|| panic!("expected sha256= in stderr; got: {stderr:?}"));
    let twelve: String = after.chars().take(12).collect();
    assert_eq!(twelve.len(), 12, "expected 12 chars after sha256=; got {twelve:?}");
    assert!(
        twelve.chars().all(|c| c.is_ascii_hexdigit()),
        "expected 12 hex chars after sha256=; got {twelve:?}",
    );
}
