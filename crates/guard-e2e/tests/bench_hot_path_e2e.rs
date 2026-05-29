// crates/guard-e2e/tests/bench_hot_path_e2e.rs
//
// v0.7 live-wrap E2E benchmark.
//
// Wraps a real `node` child via `stt-guard wrap`, loops `net.connect` against
// `registry.npmjs.org`, and prints a `LIVE_WRAP_NS p50=... p99=...` line on
// stdout that scripts/bench-hot-path.sh parses.
//
// This is the *context* number per CONTEXT D-32 — captures cache-hit +
// occasional Resolve-IPC cache-miss + TCP handshake against the real host.
// There is NO fixed budget on this number in v0.2; cache-hit p99 (the binding
// number) lives in crates/guard-hook/benches/cache_hit_hot_path.rs.
//
// Reuses guard-e2e::DaemonHarness + resolve_node/cli/dylib per CONTEXT D-34,
// mirroring the harness pattern from failure_modes_daemon_killed.rs.
//
// Gating: #[ignore] so cargo test --workspace stays fast (RESEARCH §Pitfall 7 +
// §Anti-Patterns). Invoke via:
//   cargo test -p guard-e2e --release --test bench_hot_path_e2e -- --ignored --nocapture

use std::io::{BufRead, BufReader};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use guard_e2e::{DaemonHarness, resolve_cli, resolve_dylib, resolve_node};

#[cfg_attr(
    not(target_os = "macos"),
    ignore = "macOS-only; live-wrap bench opt-in via scripts/bench-hot-path.sh"
)]
#[cfg_attr(
    target_os = "macos",
    ignore = "live-wrap bench — opt-in via scripts/bench-hot-path.sh"
)]
#[test]
fn live_wrap_npmjs_loop_p99_context() {
    let cli = resolve_cli();
    let dylib = resolve_dylib();
    let node = match resolve_node() {
        Ok(p) => p,
        Err(why) => {
            eprintln!("SKIP live_wrap_npmjs_loop_p99_context: {why}");
            return;
        }
    };
    let harness = DaemonHarness::start().expect("start daemon");

    let mut wrapped = Command::new(&cli)
        .arg("wrap")
        .arg(&node)
        .arg("-e")
        .arg(live_wrap_script())
        .env_clear()
        .env("HOME", harness.home.path())
        .env("PATH", std::env::var_os("PATH").unwrap_or_default())
        .env("STT_GUARD_HOOK_DYLIB", &dylib)
        .env("STT_GUARD_STATE_DIR", &harness.state_dir)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn stt-guard wrap");

    let stdout = wrapped.stdout.take().expect("stdout pipe");
    let mut reader = BufReader::new(stdout);

    // Drain stdout line by line, looking for the LIVE_WRAP_NS summary. Generous
    // deadline: 1000 iterations + warm-up against a real host can take 30-60s.
    let deadline = Instant::now() + Duration::from_secs(120);
    let mut summary: Option<String> = None;
    let mut all_stdout = String::new();
    while Instant::now() < deadline {
        let mut line = String::new();
        match reader.read_line(&mut line) {
            Ok(0) => break, // EOF
            Ok(_) => {
                all_stdout.push_str(&line);
                let trimmed = line.trim_end();
                if trimmed.starts_with("LIVE_WRAP_NS ") {
                    summary = Some(trimmed.to_string());
                    break;
                }
                if trimmed.starts_with("LIVE_WRAP_ERROR ") {
                    eprintln!("[live-wrap] node reported error: {trimmed}");
                    eprintln!("full stdout:\n{all_stdout}");
                    let _ = wrapped.kill();
                    let _ = wrapped.wait();
                    drop(harness);
                    panic!("live-wrap bench failed: {trimmed}");
                }
            }
            Err(e) => {
                eprintln!("[live-wrap] stdout read error: {e}");
                break;
            }
        }
    }

    let _ = wrapped.kill();
    let _ = wrapped.wait();
    drop(harness);

    if let Some(line) = summary {
        // Echo the summary to stderr in the structured shape the runner script greps.
        // (--nocapture forwards this to the user.)
        eprintln!("[live-wrap] {line}");
        // Truncate at a UTF-8 char boundary — `&all_stdout[..4096]` would
        // panic ("byte index N is not a char boundary") if byte 4096 lands
        // inside a multi-byte codepoint. The injected node script emits
        // ASCII today, but a node panic stack trace, a non-ASCII path
        // component, or future emoji in diagnostic output would otherwise
        // hide the real failure behind a slicing panic.
        let dump_end = std::cmp::min(4096, all_stdout.len());
        let dump_end = (0..=dump_end)
            .rev()
            .find(|&i| all_stdout.is_char_boundary(i))
            .unwrap_or(0);
        eprintln!(
            "[live-wrap] full stdout dump (first 4 KiB):\n{}",
            &all_stdout[..dump_end]
        );
    } else {
        eprintln!("[live-wrap] no LIVE_WRAP_NS summary observed before deadline");
        eprintln!("full stdout:\n{all_stdout}");
        panic!("live-wrap bench timed out before producing summary line");
    }
}

fn live_wrap_script() -> &'static str {
    r"
        const net = require('net');
        const ITERS = 1000;
        const samples = [];
        function one() {
            return new Promise((resolve, reject) => {
                const t0 = process.hrtime.bigint();
                const s = net.connect(443, 'registry.npmjs.org');
                s.on('connect', () => {
                    const dt = process.hrtime.bigint() - t0;
                    s.end();
                    resolve(Number(dt));
                });
                s.on('error', reject);
            });
        }
        (async () => {
            try {
                for (let i = 0; i < 50; i++) { await one(); }
                for (let i = 0; i < ITERS; i++) { samples.push(await one()); }
                samples.sort((a, b) => a - b);
                const p = q => samples[Math.floor((samples.length - 1) * q)];
                console.log('LIVE_WRAP_NS p50=' + p(0.5) +
                            ' p95=' + p(0.95) +
                            ' p99=' + p(0.99) +
                            ' p999=' + p(0.999) +
                            ' max=' + samples[samples.length - 1]);
            } catch (e) {
                console.log('LIVE_WRAP_ERROR ' + (e && e.code ? e.code : e));
                process.exitCode = 1;
            }
        })();
    "
}
