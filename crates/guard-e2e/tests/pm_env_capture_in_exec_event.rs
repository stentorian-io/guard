//! v0.1 milestone audit BLOCKER #1 (LOG-02 + VAL-01) — focused capture proof.
//!
//! Sibling to `log_writer_pm_env_denylist_e2e.rs`. That test focuses on the
//! NEGATIVE assertion (secrets must not leak); this one focuses on the
//! POSITIVE assertion (the dylib captured a known number of benign PM env
//! vars, the V3 wire frame was actually used, and the captured Vec landed on
//! a ProcessNode).
//!
//! Asserts on three structured tracing fields emitted by the daemon's
//! `ipc_server::handle_exec_event_frame` whenever a non-empty pm_env arrives:
//!   - `pm_env_captured` event name
//!   - `schema_version=3` proves the dylib's `send_exec_event_sync` upgraded
//!     IPC_SCHEMA_V2 → IPC_SCHEMA_V3 (Task 2 contract)
//!   - `captured=4` proves the four benign npm_*+CARGO_PKG_NAME pairs from
//!     the harness's envp survived BOTH filter layers
//!   - `wire_pairs=4` proves that the dylib-side filter dropped the three
//!     decoy denylisted secrets BEFORE the wire (otherwise wire_pairs would
//!     be 7 = 4 benign + 3 decoys), confirming defense-in-depth.

use guard_e2e::{DaemonHarness, cargo_target_dir, resolve_cli, resolve_dylib};
use std::process::Command;
use std::time::Duration;

#[cfg_attr(not(target_os = "macos"), ignore)]
#[test]
fn pm_env_captured_via_v3_exec_event_with_dylib_side_filter() {
    let cli = resolve_cli();
    let dylib = resolve_dylib();
    let harness_bin = cargo_target_dir().join("pm_env_posix_spawn");
    assert!(
        harness_bin.exists(),
        "pm_env_posix_spawn harness missing at {} — run `cargo build --workspace` first",
        harness_bin.display()
    );

    let mut harness = DaemonHarness::start().expect("start daemon");

    let output = Command::new(&cli)
        .arg("wrap")
        .arg(&harness_bin)
        .env_clear()
        .env("HOME", harness.home.path())
        .env("PATH", std::env::var_os("PATH").unwrap_or_default())
        .env("STT_GUARD_HOOK_DYLIB", &dylib)
        .env("STT_GUARD_STATE_DIR", &harness.state_dir)
        .output()
        .expect("run stt-guard");

    std::thread::sleep(Duration::from_millis(500));
    let stderr = harness.drain_stderr();

    // The harness injects 4 benign PM env vars + 3 decoy secrets. The
    // dylib-side filter drops the 3 decoys; the daemon receives 4 wire pairs.
    // The daemon-side re-filter is a defense-in-depth no-op here (everything
    // has already been filtered) and `captured` matches `wire_pairs`.
    assert!(
        stderr.contains("pm_env_captured"),
        "expected `pm_env_captured` info line in daemon stderr — capture did not reach handler.\n\
         wrapped harness exit: {:?}\n\
         daemon stderr:\n{stderr}",
        output.status,
    );

    // schema_version=3 proves Task 2's frame upgrade fired (V2 → V3 because
    // pm_env was non-empty).
    // tracing's fmt subscriber emits structured fields with ANSI escapes
    // around the `=`. Strip ANSI codes for substring matching so the
    // assertion is robust against formatter changes (italic markers,
    // future colorization).
    let stderr_plain = strip_ansi(&stderr);
    assert!(
        stderr_plain.contains("schema_version=3"),
        "expected schema_version=3 in daemon stderr — dylib did not upgrade frame to V3.\n\
         daemon stderr:\n{stderr}",
    );

    // captured=4 proves the daemon-side extract_pm_env emitted a 4-pair Vec
    // (the four benign npm_*+CARGO_PKG_NAME entries the harness injected).
    assert!(
        stderr_plain.contains("captured=4"),
        "expected captured=4 in daemon stderr — wrong number of PM env pairs admitted.\n\
         daemon stderr:\n{stderr}",
    );

    // wire_pairs=4 proves the dylib-side filter dropped the three decoy
    // secrets BEFORE the IPC wire. Without the dylib filter, this would be
    // 7 (4 benign + 3 decoys), and the daemon's defense-in-depth filter
    // would only then drop the secrets server-side. Asserting wire_pairs==4
    // (== captured) is the structural proof that the dylib half of the
    // BLOCKER #1 closure is actually doing its job.
    assert!(
        stderr_plain.contains("wire_pairs=4"),
        "expected wire_pairs=4 in daemon stderr — dylib-side filter did not drop decoys before wire.\n\
         daemon stderr:\n{stderr}",
    );
}

/// Strip ANSI escape sequences (CSI `\x1b[...m`) from `s`. Tracing's fmt
/// subscriber wraps structured field names + delimiters in italic markers
/// (`\x1b[2m...\x1b[0m`), which break a naive substring search like
/// `stderr.contains("schema_version=3")`. This helper removes those
/// sequences so assertions match the underlying text shape.
fn strip_ansi(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\x1b' && chars.peek() == Some(&'[') {
            chars.next(); // consume `[`
            // Skip parameter / intermediate bytes; CSI is terminated by a
            // byte in 0x40..=0x7e (`@A-Za-z[\]^_` ` `{|}~).
            for cc in chars.by_ref() {
                if ('@'..='~').contains(&cc) {
                    break;
                }
            }
            continue;
        }
        out.push(c);
    }
    out
}
