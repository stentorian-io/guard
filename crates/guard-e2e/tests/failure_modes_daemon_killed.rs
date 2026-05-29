//! Daemon-killed failure-mode e2e — v0.7.
//!
//! Asserts that when the daemon is SIGKILL'd mid-run:
//!   1. (HARD) v0.2 connect to an unknown host produces `STEP2_DENIED` on
//!      stdout — NOT `OR timeout`. The dylib's existing
//!      `RESOLVE_TIMEOUT_MS=100` + `connect_with_timeout` shape is verified
//!      deterministic against a SIGKILL'd daemon (verification spike landed at
//!      crates/guard-hook/tests/daemon_dead_socket_returns_io_error.rs
//!      — "D-38 verified: existing shape returns ECONNREFUSED in <1ms").
//!   2. (HARD) The reported error code is EHOSTUNREACH — the dylib-fired
//!      marker. Node's deadline-timeout path produces a different shape
//!      (`STEP2_TIMEOUT` without :EHOSTUNREACH); this disambiguates "dylib
//!      denied" from "node gave up" without needing a JSONL block-event row.
//!
//! disposition #3 — defer JSONL: the JSONL block-event assertion is DEFERRED
//! to v0.3. The libc-deny path in
//! `crates/guard-hook/src/replace_libc.rs:181-201` writes only to the
//! in-process `LOG_RING` (line 195) and does NOT route to `log_writer.send`;
//! the libc-allow path (line 199) is symmetrically silent. The only
//! production producer of `LogRow::Allow` / `LogRow::Block` is
//! `crates/guard-daemon/src/handlers/prompt_channel.rs:405,407`,
//! reachable only via the interactive-TUI prompt path.
//! Closing the libc → JSONL gap is a v0.3+ work item; v0.2 ships denied-only
//! stdout + EHOSTUNREACH-marker assertion as the dylib-fired evidence.
//!
//! Catastrophic regression: `STEP2_LEAKED` (the connect succeeded), which
//! would prove the dylib silently allowed an unknown host through after the
//! daemon died.
//!
//! EMPIRICAL CORRECTION (2026-05-09 verification re-run): the v0.2 first
//! attempt of this test used `unknown-host.test.invalid` (RFC 6761 reserved
//! `.invalid` TLD) on the assumption that node would call `connect()` with the
//! resolved-failure path going through `guard_connect`. The verifier showed
//! this is wrong: `getaddrinfo` returns `ENOTFOUND` for any `.invalid`
//! hostname, node short-circuits before `connect()` is called, and
//! `guard_connect` never fires (the dylib's getaddrinfo interceptor was
//! deleted per BL-05; see crates/guard-hook/src/replace_libc.rs:268-275).
//! The step-2 target is now `192.0.2.1` — RFC 5737 TEST-NET-1, an IPv4
//! literal that bypasses DNS entirely and forces node to call `connect()` with
//! a real `sockaddr_in`. This matches the pattern established at
//! crates/guard-e2e/tests/zero_config_allow_deny.rs:97 (`addr_b =
//! "192.0.2.1:80"`) and exercises the same raw-IP cache-miss-deny path
//! (Tier 0c) that produces `Verdict::Deny` → `errno = EHOSTUNREACH` →
//! `STEP2_DENIED:EHOSTUNREACH`.

use std::io::{BufRead, BufReader};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use guard_e2e::{DaemonHarness, resolve_cli, resolve_dylib, resolve_node};

struct Step2Observation {
    outcome: Option<&'static str>,
    error_code: Option<String>,
}

#[cfg_attr(not(target_os = "macos"), ignore = "macOS-only test")]
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

    // Two-step node script.
    // Step 1 connect must be ALLOWED (registry.npmjs.org is on the curated
    // allowlist via v0.2 yaml). Step 2 connect MUST be STEP2_DENIED with
    // the `:EHOSTUNREACH` suffix (v0.7 disposition #3 — denied-only,
    // dylib-fired). Step 2 targets the IPv4
    // literal `192.0.2.1` (RFC 5737 TEST-NET-1) so node skips getaddrinfo
    // and guard_connect interposes the connect() call directly; the
    // raw-IP cache-miss-deny path at replace_libc.rs:194 sets
    // errno=EHOSTUNREACH. The internal 4s setTimeout fallback that emits
    // STEP2_TIMEOUT is preserved purely as a debugging surface: under D-38
    // verification it must not fire on a healthy SIGKILL'd-daemon test
    // environment, but if it does, the outer assertion will fail with
    // `observed: Some("timeout")` and the script exits cleanly rather than
    // hanging the harness. STEP2_LEAKED remains the catastrophic regression.
    let mut wrapped = spawn_wrapped_node_probe(&cli, &node, &dylib, &harness);

    // Wait for STEP1_CONNECTED on stdout (RESEARCH §Pitfall 5 race avoidance).
    let stdout = wrapped.stdout.take().expect("stdout pipe");
    let mut br = BufReader::new(stdout);
    let mut all_stdout = String::new();
    let step1_seen = wait_for_step1_connected(&mut br, &mut all_stdout);
    assert!(
        step1_seen,
        "Step 1 never connected — daemon or registry.npmjs.org allowlisting broken;\n\
         stdout so far:\n{all_stdout}\n\
         daemon stderr:\n{}",
        harness.drain_stderr()
    );

    // The HARD KILL — daemon goes down here. After this, the dylib still has
    // the snapshot mmap'd; for known hosts it keeps enforcing; for the
    // unknown-IP target (192.0.2.1, RFC 5737), the connect path runs:
    //   guard_connect → decide_for_sockaddr → cache miss →
    //   Resolve-IPC walk fires `Err(IpcClientError::Io(ConnectionRefused))`
    //   in <1ms (D-38 verification) for each entry → falls through
    //   to evaluate_in_hook with empty host → Tier 0c raw-IP cache-miss-deny
    //   → Verdict::Deny → errno = EHOSTUNREACH; return -1.
    // Node then prints `STEP2_DENIED:EHOSTUNREACH` and exits 1. The
    // STEP2_TIMEOUT path is no longer accepted (v0.2 tightening per
    // disposition #3).
    kill_daemon(&harness);

    // Allow the SIGKILL to propagate.
    std::thread::sleep(Duration::from_millis(100));

    let step2 = read_step2_observation(&mut br, &mut all_stdout);

    // Reap the wrapped child to avoid leaking it.
    let _ = wrapped.kill();
    let _ = wrapped.wait();

    // Disposition #3 — defer JSONL: tightened from v0.1's lenient
    // `denied OR timeout` shape to denied-only. The dylib's existing
    // RESOLVE_TIMEOUT_MS=100 + connect_with_timeout shape is verified
    // deterministic against a SIGKILL'd daemon (D-38; sub-1ms
    // ECONNREFUSED → cache-miss-deny path). Pass shapes:
    //   - 'denied' with step2_error_code == Some("EHOSTUNREACH") — explicit
    //     cache-miss-deny from the dylib's libc::connect interceptor (sets
    //     `*libc::__error() = libc::EHOSTUNREACH` at replace_libc.rs:194).
    //     PROVES fail-closed and PROVES the dylib (not node's deadline) is
    //     the entity refusing the connection.
    // Fail shapes:
    //   - 'timeout' — node's internal 4s deadline. NO LONGER ACCEPTED.
    //   - 'leaked'  — connect succeeded; catastrophic.
    //   - None      — no step-2 marker before deadline; test could not
    //                 observe the outcome.
    //
    // HARD assertion 1: step 2 must be denied (no longer
    // accepting timeout).
    let pass_strict = matches!(step2.outcome, Some("denied"));
    assert!(
        pass_strict,
        "HARD: step 2 must be denied (no longer accepting timeout).\n\
         observed: {:?}\nstdout:\n{all_stdout}\ndaemon stderr:\n{}",
        step2.outcome,
        harness.drain_stderr()
    );

    // HARD assertion 2: error code is EHOSTUNREACH,
    // the dylib-fired marker. Disambiguates "dylib denied" from "node gave up".
    // STEP2_DENIED is paired with `:EHOSTUNREACH` in the node script's
    // `e.code` print; the v0.1 `STEP2_TIMEOUT` shape (which we no longer
    // accept) does not include `e.code`.
    assert!(
        all_stdout.contains("STEP2_DENIED:EHOSTUNREACH")
            || step2.error_code.as_deref() == Some("EHOSTUNREACH"),
        "expected STEP2_DENIED:EHOSTUNREACH \
         (dylib-fired); observed_outcome={:?}, observed_code={:?}\n\
         stdout:\n{all_stdout}\n\
         daemon stderr:\n{}",
        step2.outcome,
        step2.error_code,
        harness.drain_stderr()
    );

    // Drop harness — its Drop sends SIGTERM/SIGKILL to harness.child but harness.child
    // is already dead from the SIGKILL above. lib.rs:140-164 handles try_wait → SIGKILL
    // gracefully on dead pids.
    drop(harness);
}

fn spawn_wrapped_node_probe(
    cli: &std::path::Path,
    node: &std::path::Path,
    dylib: &std::path::Path,
    harness: &DaemonHarness,
) -> std::process::Child {
    Command::new(cli)
        .arg("wrap")
        .arg(node)
        .arg("-e")
        .arg(node_probe_script())
        .env_clear()
        .env("HOME", harness.home.path())
        .env("PATH", std::env::var_os("PATH").unwrap_or_default())
        .env("STT_GUARD_HOOK_DYLIB", dylib)
        .env("STT_GUARD_STATE_DIR", &harness.state_dir)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn stt-guard wrap")
}

fn node_probe_script() -> &'static str {
    r"
        const net = require('net');
        const step1 = net.connect(443, 'registry.npmjs.org');
        step1.on('connect', () => {
            step1.end();
            console.log('STEP1_CONNECTED');
            setTimeout(() => {
                const step2 = net.connect(443, '192.0.2.1');
                let resolved = false;
                step2.on('error', e => {
                    if (resolved) return;
                    resolved = true;
                    console.log('STEP2_DENIED:' + e.code);
                    process.exit(1);
                });
                step2.on('connect', () => {
                    if (resolved) return;
                    resolved = true;
                    console.log('STEP2_LEAKED');
                    process.exit(2);
                });
                setTimeout(() => {
                    if (resolved) return;
                    resolved = true;
                    console.log('STEP2_TIMEOUT');
                    process.exit(3);
                }, 4000);
            }, 2500);
        });
        step1.on('error', e => {
            console.log('STEP1_FAILED:', e.code);
            process.exit(4);
        });
    "
}

fn wait_for_step1_connected<R: std::io::Read>(
    br: &mut BufReader<R>,
    all_stdout: &mut String,
) -> bool {
    let deadline = Instant::now() + Duration::from_secs(20);
    while Instant::now() < deadline {
        let mut line = String::new();
        match br.read_line(&mut line) {
            Ok(0) | Err(_) => break,
            Ok(_) => {
                all_stdout.push_str(&line);
                if line.contains("STEP1_CONNECTED") {
                    return true;
                }
                if line.contains("STEP1_FAILED") {
                    break;
                }
            }
        }
    }

    false
}

fn kill_daemon(harness: &DaemonHarness) {
    let daemon_pid = libc::pid_t::try_from(harness.child.id()).expect("daemon pid fits libc pid");
    unsafe {
        libc::kill(daemon_pid, libc::SIGKILL);
    }
}

fn read_step2_observation<R: std::io::Read>(
    br: &mut BufReader<R>,
    all_stdout: &mut String,
) -> Step2Observation {
    let deadline = Instant::now() + Duration::from_secs(15);
    while Instant::now() < deadline {
        let mut line = String::new();
        match br.read_line(&mut line) {
            Ok(0) | Err(_) => break,
            Ok(_) => {
                all_stdout.push_str(&line);
                if line.contains("STEP2_DENIED:") {
                    return Step2Observation {
                        outcome: Some("denied"),
                        error_code: denied_error_code(&line),
                    };
                }
                if line.contains("STEP2_TIMEOUT") {
                    return Step2Observation {
                        outcome: Some("timeout"),
                        error_code: None,
                    };
                }
                if line.contains("STEP2_LEAKED") {
                    return Step2Observation {
                        outcome: Some("leaked"),
                        error_code: None,
                    };
                }
            }
        }
    }

    Step2Observation {
        outcome: None,
        error_code: None,
    }
}

fn denied_error_code(line: &str) -> Option<String> {
    let rest = line.find("STEP2_DENIED:")?;
    let after = &line[rest + "STEP2_DENIED:".len()..];
    let code = after.trim().trim_end_matches(',').to_string();
    (!code.is_empty()).then_some(code)
}
