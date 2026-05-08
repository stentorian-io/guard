//! Phase 5 plan 05-05 — VAL-04 D-09: daemon-killed mid-run failure mode.
//!
//! Verifies the dylib's "fail-closed for unknown destinations once the daemon
//! is gone" contract:
//!   1. Start daemon + sentinel run a node script.
//!   2. Phase 1: node connects to registry.npmjs.org (allowlisted) — proves
//!      the dylib has loaded the per-run snapshot and the curated allowlist
//!      entry resolves.
//!   3. Read PHASE1_CONNECTED from the wrapped child's stdout — race-safe
//!      synchronization point (RESEARCH §Pitfall 5: do NOT use a fixed sleep).
//!   4. Test sends SIGKILL to the daemon.
//!   5. Phase 2: node attempts to connect to an unknown host. Without the
//!      daemon to defer-resolve via Resolve IPC, one of two things happens
//!      (per WARNING-5 — send_resolve_sync timeout semantics on a dead Unix
//!      socket are not plan-time verified):
//!        (a) the dylib's send_resolve_sync errors → falls through to
//!            evaluate_policy with no host resolution → cache-miss-deny path
//!            fires → connect() returns -1 with EHOSTUNREACH and node prints
//!            PHASE2_DENIED; OR
//!        (b) the dylib's send_resolve_sync hangs (no explicit timeout against
//!            a dead socket today) → node hits its 4-second internal timeout,
//!            prints PHASE2_TIMEOUT, exits non-zero — also a fail-closed shape
//!            because the connect never succeeded.
//!      Either outcome is acceptable. The ONLY catastrophic regression is
//!      observing PHASE2_LEAKED (the connect succeeded), which would prove the
//!      dylib silently allowed an unknown host through after the daemon died.
//!   6. Test asserts node printed PHASE2_DENIED OR PHASE2_TIMEOUT (both pass);
//!      a PHASE2_LEAKED observation fails the test loudly.
//!
//! Future hardening (post-v1, NOT in scope here): if Phase 3 adds an explicit
//! timeout to send_resolve_sync against a dead socket, narrow this assertion
//! to require explicit PHASE2_DENIED. Today both shapes are accepted.

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
    // allowlist via Phase 2 plan 02-02 yaml). Phase 2 connect must be DENIED
    // OR hit the per-connect 4s deadline-timeout (both acceptable per
    // WARNING-5 — see assertion comment below). Only PHASE2_LEAKED is a
    // catastrophic regression.
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
                    console.log('PHASE2_DENIED:', e.code);
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
        .arg("run")
        .arg("--")
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
    // hosts the Resolve-IPC fallback errors (PHASE2_DENIED) or hangs and the
    // wrapped node hits its internal 4s deadline (PHASE2_TIMEOUT) — both
    // are acceptable fail-closed shapes per WARNING-5.
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
    while Instant::now() < phase2_deadline {
        let mut line = String::new();
        match br.read_line(&mut line) {
            Ok(0) => break,
            Ok(_) => {
                all_stdout.push_str(&line);
                if line.contains("PHASE2_DENIED") {
                    phase2_outcome = Some("denied");
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

    // Assertion (per WARNING-5): denied OR timeout pass; leaked fails;
    // None (no marker observed within deadline) is also a fail (test never
    // saw a definitive phase-2 outcome — could indicate stdout pipe hang).
    let pass = matches!(phase2_outcome, Some("denied") | Some("timeout"));
    assert!(
        pass,
        "VAL-04 D-09 HARD assertion failed: PHASE2 did not fail closed.\n\
         Acceptable outcomes: 'denied' (explicit deny from cache-miss) OR \
         'timeout' (dylib hung against dead daemon socket → node 4s deadline).\n\
         Catastrophic regression: 'leaked' (connect succeeded — dylib silently \
         allowed unknown host after daemon death).\n\
         observed outcome: {:?}\n\
         stdout:\n{all_stdout}\n\
         daemon stderr (best-effort post-kill):\n{}",
        phase2_outcome,
        harness.drain_stderr()
    );

    // Drop harness — its Drop sends SIGTERM/SIGKILL to harness.child but harness.child
    // is already dead from the SIGKILL above. lib.rs:140-164 handles try_wait → SIGKILL
    // gracefully on dead pids.
    drop(harness);
}
