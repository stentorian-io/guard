//! Daemon-killed failure-mode e2e — Phase 08 / VAL-05 D-39 + D-38.
//!
//! Asserts that when the daemon is SIGKILL'd mid-run:
//!   1. (HARD) Phase 2 connect to an unknown host produces PHASE2_DENIED on
//!      stdout — NOT `OR timeout`. The dylib's existing
//!      `RESOLVE_TIMEOUT_MS=100` + `connect_with_timeout` shape is verified
//!      deterministic against a SIGKILL'd daemon (Phase 08 D-38; verification
//!      spike landed at
//!      crates/sentinel-hook/tests/daemon_dead_socket_returns_io_error.rs and
//!      annotated in
//!      .planning/phases/08-perf-reliability-hardening/08-CONTEXT.md near D-40
//!      — "D-38 verified: existing shape returns ECONNREFUSED in <1ms").
//!   2. (HARD) The reported error code is EHOSTUNREACH — the dylib-fired
//!      marker. Node's deadline-timeout path produces a different shape
//!      (PHASE2_TIMEOUT without :EHOSTUNREACH); this disambiguates "dylib
//!      denied" from "node gave up" without needing a JSONL block-event row.
//!
//! disposition #3 — defer JSONL: the JSONL block-event assertion is DEFERRED
//! to v0.3 per Phase 08 D-39 disposition #3. The libc-deny path in
//! `crates/sentinel-hook/src/replace_libc.rs:181-201` writes only to the
//! in-process LOG_RING (line 195) and does NOT route to `log_writer.send`;
//! the libc-allow path (line 199) is symmetrically silent. The only
//! production producer of `LogRow::Allow` / `LogRow::Block` is
//! `crates/sentinel-daemon/src/handlers/prompt_channel.rs:405,407`,
//! reachable only via the interactive-TUI prompt path. Audit trail:
//! .planning/phases/08-perf-reliability-hardening/08-AUDIT-libc-allow-jsonl.md.
//! Closing the libc → JSONL gap is a v0.3+ work item; v0.2 ships denied-only
//! stdout + EHOSTUNREACH-marker assertion as the dylib-fired evidence.
//!
//! Catastrophic regression: PHASE2_LEAKED (the connect succeeded), which
//! would prove the dylib silently allowed an unknown host through after the
//! daemon died.

use std::io::{BufRead, BufReader};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use sentinel_e2e::{resolve_cli, resolve_dylib, resolve_node, DaemonHarness};

#[cfg_attr(not(target_os = "macos"), ignore)]
#[test]
fn daemon_killed_mid_run_keeps_enforcing_known_hosts_then_fails_closed() {
    let cli = resolve_cli();
    let dylib = resolve_dylib();
    let node = match resolve_node() {
        Ok(p) => p,
        Err(why) => {
            eprintln!("SKIP daemon_killed_mid_run: {why}");
            return;
        }
    };
    let mut harness = DaemonHarness::start().expect("start daemon");

    // Two-phase node script (RESEARCH §Code Examples §A lines 441-454).
    // Phase 1 connect must be ALLOWED (registry.npmjs.org is on the curated
    // allowlist via Phase 2 plan 02-02 yaml). Phase 2 connect must be
    // PHASE2_DENIED with the `:EHOSTUNREACH` suffix (Phase 08 D-39
    // disposition #3 — denied-only, dylib-fired). The internal 4s
    // setTimeout fallback that emits PHASE2_TIMEOUT is preserved purely as
    // a debugging surface: under D-38 verification it must not fire on a
    // healthy SIGKILL'd-daemon test environment, but if it does, the outer
    // assertion will fail with `observed: Some("timeout")` and the script
    // exits cleanly rather than hanging the harness. PHASE2_LEAKED remains
    // the catastrophic regression.
    let script = r#"
        const net = require('net');
        const phase1 = net.connect(443, 'registry.npmjs.org');
        phase1.on('connect', () => {
            phase1.end();
            console.log('PHASE1_CONNECTED');
            // 2.5s gives the test harness ample time to read PHASE1_CONNECTED
            // (race-free; RESEARCH §Pitfall 5) and send SIGKILL.
            setTimeout(() => {
                const phase2 = net.connect(443, 'unknown-host.test.invalid');
                let resolved = false;
                phase2.on('error', e => {
                    if (resolved) return;
                    resolved = true;
                    // Concatenated form (no space) so the test can match
                    // `PHASE2_DENIED:EHOSTUNREACH` as a single token. Phase 08
                    // D-39 disposition #3: the EHOSTUNREACH suffix is the
                    // dylib-fired marker that disambiguates dylib denial from
                    // node's deadline-timeout exit.
                    console.log('PHASE2_DENIED:' + e.code);
                    process.exit(1);
                });
                phase2.on('connect', () => {
                    if (resolved) return;
                    resolved = true;
                    console.log('PHASE2_LEAKED');
                    process.exit(2);
                });
                // Internal 4s deadline — fires if the dylib hangs the connect
                // (e.g. send_resolve_sync awaits a dead socket without an
                // explicit timeout). Treated as fail-closed by the outer test.
                setTimeout(() => {
                    if (resolved) return;
                    resolved = true;
                    console.log('PHASE2_TIMEOUT');
                    process.exit(3);
                }, 4000);
            }, 2500);
        });
        phase1.on('error', e => {
            console.log('PHASE1_FAILED:', e.code);
            process.exit(4);
        });
    "#;

    let mut wrapped = Command::new(&cli)
        .arg(&node)
        .arg("-e")
        .arg(script)
        .env_clear()
        .env("HOME", harness.home.path())
        .env("PATH", std::env::var_os("PATH").unwrap_or_default())
        .env("SENTINEL_HOOK_DYLIB", &dylib)
        .env("SENTINEL_STATE_DIR", &harness.state_dir)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn sentinel run");

    // Wait for PHASE1_CONNECTED on stdout (RESEARCH §Pitfall 5 race avoidance).
    let stdout = wrapped.stdout.take().expect("stdout pipe");
    let mut br = BufReader::new(stdout);
    let mut all_stdout = String::new();
    let deadline = Instant::now() + Duration::from_secs(20);
    let mut phase1_seen = false;
    while Instant::now() < deadline {
        let mut line = String::new();
        match br.read_line(&mut line) {
            Ok(0) => break,
            Ok(_) => {
                all_stdout.push_str(&line);
                if line.contains("PHASE1_CONNECTED") {
                    phase1_seen = true;
                    break;
                }
                if line.contains("PHASE1_FAILED") {
                    break;
                }
            }
            Err(_) => break,
        }
    }
    assert!(
        phase1_seen,
        "PHASE1 never connected — daemon or registry.npmjs.org allowlisting broken;\n\
         stdout so far:\n{all_stdout}\n\
         daemon stderr:\n{}",
        harness.drain_stderr()
    );

    // The HARD KILL — daemon goes down here. After this, the dylib still has
    // the snapshot mmap'd; for known hosts it keeps enforcing; for unknown
    // hosts the Resolve-IPC fast-shape fires `Err(IpcClientError::Io(
    // ConnectionRefused))` in <1ms (Phase 08 D-38 verification), the dylib
    // falls through to cache-miss-deny, and `connect()` returns -1 with
    // `errno = EHOSTUNREACH` — node prints `PHASE2_DENIED:EHOSTUNREACH`
    // and exits 1. The PHASE2_TIMEOUT path is no longer accepted (v0.2
    // tightening per D-39 disposition #3).
    let daemon_pid = harness.child.id() as libc::pid_t;
    unsafe {
        libc::kill(daemon_pid, libc::SIGKILL);
    }
    // Allow the SIGKILL to propagate.
    std::thread::sleep(Duration::from_millis(100));

    // Continue reading stdout until child exits OR we observe one of the
    // phase-2 markers. Outer deadline is 15s after the kill (the inner script
    // has 2.5s setTimeout + up to 4s connect deadline).
    let phase2_deadline = Instant::now() + Duration::from_secs(15);
    let mut phase2_outcome: Option<&'static str> = None;
    // VAL-05 D-39 disposition #3: extract the `e.code` suffix from the node
    // script's `PHASE2_DENIED:<code>` line. EHOSTUNREACH is the dylib-fired
    // marker; any other code (or absence of a code) indicates the deny did
    // not come from the dylib's interceptor.
    let mut phase2_error_code: Option<String> = None;
    while Instant::now() < phase2_deadline {
        let mut line = String::new();
        match br.read_line(&mut line) {
            Ok(0) => break,
            Ok(_) => {
                all_stdout.push_str(&line);
                if let Some(rest) = line.find("PHASE2_DENIED:") {
                    phase2_outcome = Some("denied");
                    // Extract the `<code>` suffix after `PHASE2_DENIED:`.
                    // The node script emits `PHASE2_DENIED:` + e.code with
                    // no separator; e.code can be undefined (rendered as
                    // "undefined") or a real errno string like
                    // "EHOSTUNREACH".
                    let after = &line[rest + "PHASE2_DENIED:".len()..];
                    let code = after.trim().trim_end_matches(',').to_string();
                    if !code.is_empty() {
                        phase2_error_code = Some(code);
                    }
                    break;
                }
                if line.contains("PHASE2_TIMEOUT") {
                    phase2_outcome = Some("timeout");
                    break;
                }
                if line.contains("PHASE2_LEAKED") {
                    phase2_outcome = Some("leaked");
                    break;
                }
            }
            Err(_) => break,
        }
    }

    // Reap the wrapped child to avoid leaking it.
    let _ = wrapped.kill();
    let _ = wrapped.wait();

    // VAL-05 D-39 disposition #3 — defer JSONL: tightened from v0.1's lenient
    // `denied OR timeout` shape to denied-only. The dylib's existing
    // RESOLVE_TIMEOUT_MS=100 + connect_with_timeout shape is verified
    // deterministic against a SIGKILL'd daemon (Phase 08 D-38; sub-1ms
    // ECONNREFUSED → cache-miss-deny path). Pass shapes:
    //   - 'denied' with phase2_error_code == Some("EHOSTUNREACH") — explicit
    //     cache-miss-deny from the dylib's libc::connect interceptor (sets
    //     `*libc::__error() = libc::EHOSTUNREACH` at replace_libc.rs:194).
    //     PROVES fail-closed and PROVES the dylib (not node's deadline) is
    //     the entity refusing the connection.
    // Fail shapes:
    //   - 'timeout' — node's internal 4s deadline. NO LONGER ACCEPTED.
    //   - 'leaked'  — connect succeeded; catastrophic.
    //   - None      — no phase-2 marker before deadline; test could not
    //                 observe the outcome.
    //
    // VAL-05 D-39 HARD assertion 1: PHASE2 must be denied (no longer
    // accepting timeout).
    let pass_strict = matches!(phase2_outcome, Some("denied"));
    assert!(
        pass_strict,
        "VAL-05 D-39 HARD: PHASE2 must be denied (no longer accepting timeout).\n\
         observed: {:?}\nstdout:\n{all_stdout}\ndaemon stderr:\n{}",
        phase2_outcome,
        harness.drain_stderr()
    );

    // VAL-05 D-39 disposition #3 HARD assertion 2: error code is EHOSTUNREACH,
    // the dylib-fired marker. Disambiguates "dylib denied" from "node gave up".
    // PHASE2_DENIED is paired with `:EHOSTUNREACH` in the node script's
    // `e.code` print; the v0.1 `PHASE2_TIMEOUT` shape (which we no longer
    // accept) does not include `e.code`.
    assert!(
        all_stdout.contains("PHASE2_DENIED:EHOSTUNREACH")
            || phase2_error_code.as_deref() == Some("EHOSTUNREACH"),
        "VAL-05 D-39 disposition #3: expected PHASE2_DENIED:EHOSTUNREACH \
         (dylib-fired); observed_outcome={:?}, observed_code={:?}\n\
         stdout:\n{all_stdout}\n\
         daemon stderr:\n{}",
        phase2_outcome,
        phase2_error_code,
        harness.drain_stderr()
    );

    // Drop harness — its Drop sends SIGTERM/SIGKILL to harness.child but harness.child
    // is already dead from the SIGKILL above. lib.rs:140-164 handles try_wait → SIGKILL
    // gracefully on dead pids.
    drop(harness);
}
