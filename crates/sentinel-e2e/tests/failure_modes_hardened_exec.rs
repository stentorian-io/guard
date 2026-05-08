//! Phase 5 plan 05-06 — VAL-04 D-10 + CONTEXT C-05: hardened-binary failure mode.
//!
//! Verifies that when a wrapped command exec's into an Apple-signed
//! hardened-runtime binary, DYLD env vars are stripped and Sentinel detects
//! and surfaces the coverage gap. The gap appears in three places:
//!   - daemon stderr (tracing event with marker `hardened-runtime`)
//!   - JSONL log (Gap row with `gap_kind = "hardened-runtime"`)
//!   - `sentinel status --verbose` output (recent_gaps surface)
//!
//! Per CONTEXT C-05: verify `codesign -dv /usr/bin/python3` at test-time and
//! fall back to `/usr/bin/security` (always Apple-signed, hardened-runtime
//! guaranteed) if python3's codesign output doesn't show the runtime flag.

use std::path::PathBuf;
use std::process::Command;
use std::time::Duration;

use sentinel_e2e::{resolve_cli, resolve_dylib, DaemonHarness};

#[cfg_attr(not(target_os = "macos"), ignore)]
#[test]
fn hardened_runtime_exec_surfaces_coverage_gap() {
    let cli = resolve_cli();
    let dylib = resolve_dylib();
    let mut harness = DaemonHarness::start().expect("start daemon");

    let target = pick_hardened_binary();
    eprintln!("[VAL-04 D-10] hardened target = {}", target.display());

    // Spawn `sentinel run -- $target …`. For /usr/bin/security we use
    // `list-keychains` (a near-noop command that doesn't require interactive
    // input). For /usr/bin/python3 we use `--version`.
    let target_args: &[&str] = if target.ends_with("python3") {
        &["--version"]
    } else {
        // /usr/bin/security
        &["list-keychains"]
    };

    let out = Command::new(&cli)
        .arg(&target)
        .args(target_args)
        .env_clear()
        .env("HOME", harness.home.path())
        .env("PATH", std::env::var_os("PATH").unwrap_or_default())
        .env("SENTINEL_HOOK_DYLIB", &dylib)
        .env("SENTINEL_STATE_DIR", &harness.state_dir)
        .output()
        .expect("run sentinel");
    // The wrapped command may succeed (the dylib doesn't load into hardened so
    // there's nothing to enforce), or it may fail for unrelated reasons. We
    // don't HARD-assert on exit code here; the gap-detection assertion is
    // what matters.
    eprintln!("[VAL-04 D-10] target exit: {:?}", out.status.code());
    eprintln!(
        "[VAL-04 D-10] target stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    // Allow gap_detector + log_writer mpsc to drain (env_not_propagated.rs
    // canon: 500ms margin).
    std::thread::sleep(Duration::from_millis(500));

    // -----------------------------------------------------------------------
    // ASSERTION 1: daemon stderr carries a tracing event mentioning hardened-runtime.
    // -----------------------------------------------------------------------
    let stderr = harness.drain_stderr();
    let stderr_lc = stderr.to_ascii_lowercase();
    assert!(
        stderr_lc.contains("hardened-runtime"),
        "daemon stderr missing hardened-runtime marker.\nstderr:\n{stderr}",
    );

    // -----------------------------------------------------------------------
    // ASSERTION 2: JSONL log carries a Gap row with gap_kind=hardened-runtime.
    // -----------------------------------------------------------------------
    let log = harness
        .home
        .path()
        .join("Library/Logs/Sentinel/sentinel.log");
    let content = std::fs::read_to_string(&log).unwrap_or_default();
    let has_gap_row = content.lines().any(|l| {
        l.contains(r#""gap_kind":"hardened-runtime""#)
            || l.contains(r#""gap_kind": "hardened-runtime""#)
    });
    assert!(
        has_gap_row,
        "no JSONL Gap row with gap_kind=hardened-runtime;\n\
         log path: {}\n\
         contents:\n{content}\n\
         daemon stderr:\n{stderr}",
        log.display()
    );

    // -----------------------------------------------------------------------
    // ASSERTION 3: `sentinel status --verbose` surfaces the gap.
    // -----------------------------------------------------------------------
    let status_out = Command::new(&cli)
        .arg("status")
        .arg("--verbose")
        .env_clear()
        .env("HOME", harness.home.path())
        .env("SENTINEL_STATE_DIR", &harness.state_dir)
        .env("PATH", std::env::var_os("PATH").unwrap_or_default())
        .output()
        .expect("run sentinel status --verbose");
    let status_stdout = String::from_utf8_lossy(&status_out.stdout);
    let status_lc = status_stdout.to_ascii_lowercase();
    // WR-08: tighten ASSERTION 3. The previous predicate ('hardened' OR
    // 'gap') was too lenient — 'gap' is a broad word that could match any
    // unrelated text in verbose status output (e.g. 'language gap',
    // 'release gap', help-text mentioning gaps). Match the exact markers
    // that sentinel-cli/src/status.rs:188-197 emits:
    //   - 'Recent gaps (N):' header
    //   - 'hardened-runtime' (the literal gap_kind printed in column 1)
    // We require BOTH the section header AND the specific gap_kind, so a
    // pristine verbose status with no gaps does NOT pass.
    let has_recent_gaps_header = status_lc.contains("recent gaps");
    let has_hardened_runtime_kind = status_lc.contains("hardened-runtime");
    assert!(
        has_recent_gaps_header && has_hardened_runtime_kind,
        "sentinel status --verbose did not surface the hardened-runtime gap;\n\
         expected: 'Recent gaps (' header AND 'hardened-runtime' gap_kind\n\
         has_recent_gaps_header={has_recent_gaps_header} \
         has_hardened_runtime_kind={has_hardened_runtime_kind}\n\
         status stdout:\n{status_stdout}\n\
         daemon stderr:\n{stderr}",
    );

    drop(harness);
}

/// Pick the hardened-runtime binary to wrap. Per CONTEXT C-05 verify
/// `codesign -dv /usr/bin/python3`; fall back to `/usr/bin/security` if the
/// output doesn't include the `runtime` flag.
fn pick_hardened_binary() -> PathBuf {
    let python3 = PathBuf::from("/usr/bin/python3");
    if !python3.exists() {
        // python3 not installed at /usr/bin — fall back immediately.
        return PathBuf::from("/usr/bin/security");
    }

    let cs = std::process::Command::new("/usr/bin/codesign")
        .arg("-dv")
        .arg(&python3)
        .output();
    let stderr = match cs {
        Ok(o) => String::from_utf8_lossy(&o.stderr).to_string(),
        Err(_) => return PathBuf::from("/usr/bin/security"),
    };

    // codesign prints lines like:
    //   CodeDirectory v=20500 size=... flags=0x10000(runtime) ...
    // We want both `flags=` and `runtime` substring (in either order).
    if stderr.contains("flags=") && stderr.to_ascii_lowercase().contains("runtime") {
        python3
    } else {
        eprintln!(
            "[VAL-04 D-10 + C-05] /usr/bin/python3 codesign output ambiguous \
             (no `flags=…runtime` line); falling back to /usr/bin/security.\n\
             codesign stderr:\n{stderr}"
        );
        PathBuf::from("/usr/bin/security")
    }
}
