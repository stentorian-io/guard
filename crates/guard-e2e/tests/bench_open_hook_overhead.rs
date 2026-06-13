#![cfg(target_os = "macos")]

//! M003-S08: open/openat hook overhead benchmark.
//!
//! Measures the overhead of the `open()` interpose on non-persistence paths
//! (the common case — 99%+ of opens are to normal files). The hook must
//! classify the path, determine it's not a persistence target, and call
//! through to the real `open()` with negligible overhead.
//!
//! Marked #[ignore] — opt-in via `cargo test -p guard-e2e --test bench_open_hook_overhead -- --ignored --nocapture`

use guard_e2e::{DaemonHarness, resolve_cli, resolve_dylib, resolve_probe};
use std::process::Command;
use std::time::Instant;

const BENCH_RUNS: usize = 20;

#[cfg_attr(
    not(target_os = "macos"),
    ignore = "M003-S08 open hook overhead bench — opt-in via --ignored"
)]
#[test]
fn open_hook_overhead_normal_files() {
    let harness = DaemonHarness::start().expect("start daemon");
    let cli = resolve_cli();
    let dylib = resolve_dylib();
    let home = harness.home.path();

    let probe = resolve_probe();

    // Warm up: one run to populate caches
    let warmup_file = home.join("warmup.txt");
    let _ = Command::new(&cli)
        .arg("wrap")
        .arg(&probe)
        .arg(warmup_file.to_str().unwrap())
        .env_clear()
        .env("HOME", home)
        .env("PATH", std::env::var_os("PATH").unwrap_or_default())
        .env("STT_GUARD_HOOK_DYLIB", &dylib)
        .env("STT_GUARD_STATE_DIR", &harness.state_dir)
        .output()
        .expect("warmup");

    // Measure: N sequential runs writing to normal (non-persistence) paths
    let mut durations = Vec::with_capacity(BENCH_RUNS);

    for i in 0..BENCH_RUNS {
        let target = home.join(format!("bench-{i}.txt"));
        let start = Instant::now();
        let output = Command::new(&cli)
            .arg("wrap")
            .arg(&probe)
            .arg(target.to_str().unwrap())
            .env_clear()
            .env("HOME", home)
            .env("PATH", std::env::var_os("PATH").unwrap_or_default())
            .env("STT_GUARD_HOOK_DYLIB", &dylib)
            .env("STT_GUARD_STATE_DIR", &harness.state_dir)
            .output()
            .expect("bench run");
        let elapsed = start.elapsed();
        assert!(output.status.success(), "bench run {i} failed");
        durations.push(elapsed);
    }

    durations.sort();
    let p50 = durations[BENCH_RUNS / 2];
    let p95_index = (BENCH_RUNS * 95).div_ceil(100).saturating_sub(1);
    let p95 = durations[p95_index];
    let max = durations[BENCH_RUNS - 1];

    eprintln!("OPEN_HOOK_BENCH n={BENCH_RUNS} p50={p50:?} p95={p95:?} max={max:?}");

    // Sanity: each run (process spawn + open + write + exit) should complete
    // in under 2 seconds. The open() hook itself should add < 100µs but we
    // measure end-to-end (includes process spawn overhead).
    assert!(
        p95 < std::time::Duration::from_secs(2),
        "p95 too slow: {p95:?} — suggests open hook regression"
    );
}
