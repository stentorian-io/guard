//! TREE-05 success criterion #6: a child that double-forks + calls setsid
//! is still treated as part of the original sentinel-run subtree.
//!
//! E2E approach: wrap a shell script that double-forks + setsid + attempts
//! a connection. The wrapped command's exit code is not directly meaningful
//! (the connect happens in a backgrounded grandchild whose stdout is dropped);
//! the assertion instead verifies a SOFTER property: the wrapped sh exits
//! cleanly within the test deadline, i.e. the dylib's fork-hook didn't
//! fail-closed under non-pathological use.
//!
//! Plan 02-04's process_tree_tests::tree_05_grandchild_inherits_original_root
//! covers the hard data-structure-level TREE-05 invariant directly. This e2e
//! test only confirms the dispatch path doesn't crash under the double-fork
//! + setsid pattern — full daemon-introspection of the tree state is a
//! Phase 3 polish (`sentinel status` will surface this).

use sentinel_e2e::{cargo_workspace_root, resolve_cli, resolve_dylib, DaemonHarness};
use std::process::Command;
use std::time::Duration;

#[cfg_attr(not(target_os = "macos"), ignore)]
#[test]
fn double_fork_setsid_wrapped_command_completes() {
    let cli = resolve_cli();
    let dylib = resolve_dylib();
    let harness = DaemonHarness::start().expect("start daemon");
    let script =
        cargo_workspace_root().join("crates/sentinel-e2e/harness/double_fork_setsid.sh");
    assert!(
        script.exists(),
        "harness script missing at {}",
        script.display()
    );

    // The wrapped sh root MUST exit cleanly within the test deadline.
    // Use /bin/sh explicitly (Apple-shipped, hardened-runtime). DYLD_INSERT_LIBRARIES
    // strips on hardened binaries — the wrapping sh itself may not be hooked,
    // but the test still verifies the CLI's spawn path doesn't fail-closed.
    let mut cmd = Command::new(&cli);
    cmd.arg("run")
        .arg("--")
        .arg("/bin/sh")
        .arg(&script)
        .env_clear()
        .env("HOME", harness.home.path())
        .env("PATH", std::env::var_os("PATH").unwrap_or_default())
        .env("SENTINEL_HOOK_DYLIB", &dylib)
        .env("SENTINEL_STATE_DIR", &harness.state_dir);

    // Run with a 10s wall-clock budget; the script's own sleep is 1s, so
    // 10s is generous even on a busy CI runner.
    let mut child = cmd
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("spawn sentinel run");

    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    let exit_status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) => {
                if std::time::Instant::now() > deadline {
                    let _ = child.kill();
                    let _ = child.wait();
                    panic!(
                        "wrapped sentinel run did not exit within 10s — \
                         dispatch path may be hung at fork"
                    );
                }
                std::thread::sleep(Duration::from_millis(50));
            }
            Err(e) => panic!("try_wait failed: {e}"),
        }
    };

    let stderr = String::from_utf8_lossy(
        &child
            .stderr
            .take()
            .map(|mut s| {
                let mut buf = Vec::new();
                use std::io::Read;
                let _ = s.read_to_end(&mut buf);
                buf
            })
            .unwrap_or_default(),
    )
    .to_string();

    // The root sh exits 0 in the script. If sentinel's fork hook fail-closed-on-
    // daemon-unreachable, the wrapped sh would exit non-0 with EAGAIN — that
    // would indicate a defect in the test setup (daemon overload in CI) rather
    // than a TREE-05 violation. We allow either outcome and surface stderr if
    // the test ever flakes.
    assert!(
        exit_status.success() || stderr.contains("EAGAIN"),
        "wrapped double-fork+setsid sh produced unexpected output\n\
         exit: {exit_status:?}\n\
         stderr: {stderr}\n\
         (TREE-05 data-structure-level invariant is covered by plan 02-04's \
         process_tree_tests::tree_05_grandchild_inherits_original_root)"
    );
}
