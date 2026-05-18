//! M003-S08: open/openat hook overhead benchmark.
//!
//! Measures the overhead of the open() interpose on non-persistence paths
//! (the common case — 99%+ of opens are to normal files). The hook must
//! classify the path, determine it's not a persistence target, and call
//! through to the real open() with negligible overhead.
//!
//! Marked #[ignore] — opt-in via `cargo test -p sentinel-e2e --test bench_open_hook_overhead -- --ignored --nocapture`

use sentinel_e2e::{resolve_cli, resolve_dylib, resolve_probe, DaemonHarness};
use std::process::Command;
use std::time::Instant;

#[cfg_attr(not(target_os = "macos"), ignore = "M003-S08 open hook overhead bench — opt-in via --ignored")]
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
        .env("SENTINEL_HOOK_DYLIB", &dylib)
        .env("SENTINEL_STATE_DIR", &harness.state_dir)
        .output()
        .expect("warmup");

    // Measure: N sequential runs writing to normal (non-persistence) paths
    const N: usize = 20;
    let mut durations = Vec::with_capacity(N);

    for i in 0..N {
        let target = home.join(format!("bench-{i}.txt"));
        let start = Instant::now();
        let output = Command::new(&cli)
            .arg("wrap")
            .arg(&probe)
            .arg(target.to_str().unwrap())
            .env_clear()
            .env("HOME", home)
            .env("PATH", std::env::var_os("PATH").unwrap_or_default())
            .env("SENTINEL_HOOK_DYLIB", &dylib)
            .env("SENTINEL_STATE_DIR", &harness.state_dir)
            .output()
            .expect("bench run");
        let elapsed = start.elapsed();
        assert!(output.status.success(), "bench run {i} failed");
        durations.push(elapsed);
    }

    durations.sort();
    let p50 = durations[N / 2];
    let p95 = durations[(N as f64 * 0.95) as usize];
    let max = durations[N - 1];

    eprintln!("OPEN_HOOK_BENCH n={N} p50={p50:?} p95={p95:?} max={max:?}");

    // Sanity: each run (process spawn + open + write + exit) should complete
    // in under 2 seconds. The open() hook itself should add < 100µs but we
    // measure end-to-end (includes process spawn overhead).
    assert!(
        p95 < std::time::Duration::from_secs(2),
        "p95 too slow: {p95:?} — suggests open hook regression"
    );
}
