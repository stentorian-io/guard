//! Run the criterion microbench and verify it compiles and runs.
//! ENF-06 success criterion #4: formal benchmark on real hardware lands in
//! v0.5; this v0.1 test is a regression detector.

use std::process::Command;

#[cfg_attr(not(target_os = "macos"), ignore = "macOS-only test")]
#[test]
fn hot_path_microbench_compiles_and_runs() {
    let cargo = std::env::var_os("CARGO").map_or_else(
        || std::path::PathBuf::from("cargo"),
        std::path::PathBuf::from,
    );
    let mut cmd = Command::new(cargo);
    cmd.args([
        "bench",
        "-p",
        "guard-hook",
        "--bench",
        "hot_path",
        "--",
        "--profile-time=1",
    ]);
    let out = cmd.output().expect("cargo bench");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        out.status.success(),
        "cargo bench must succeed; stdout:\n{stdout}\nstderr:\n{stderr}"
    );
    // We don't enforce a numerical latency ceiling here -- that's v0.5's
    // job (formal benchmark). v0.1 just verifies the bench compiles
    // and runs on the build machine; the criterion HTML report under
    // target/criterion/ is the deliverable for ENF-06.
}
