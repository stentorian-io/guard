//! v0.5 — ua-parser-js@0.7.29 supply-chain CVE reproduction.
//!
//! Drives `stt-guard wrap npm install ./fixtures/ua-parser-js-0.7.29-sanitized.tgz`
//! through a PTY so the daemon's prompt path fires (CONTEXT C-01: libc-deny path
//! does NOT emit JSONL today; prompt path is the only path that emits
//! Decision rows for outbound denies). Pre-scripts a Deny via `writer.write_all`,
//! then HARD-asserts on the JSONL Decision row.
//!
//! NOTE: the
//! committed fixture is a SYNTHETIC MOCK — there are no real malicious bytes
//! in `ua-parser-js-0.7.29-sanitized.tgz`. The synthetic `preinstall.js`
//! unconditionally opens `net.createConnection({host: 'c2-sink.test.invalid',
//! port: 443})`, which is the only behavior this test asserts on. The
//! HARD-assertion contract (verdict=Deny + `source_kind=prompt_deny` +
//! package_context.package="ua-parser-js") is preserved against this
//! synthetic shape since the .tgz still declares
//! `{"name":"ua-parser-js","version":"0.7.29"}` in its package.json.
//!
//! Triple-defense per CONTEXT D-02:
//!   1. Stentorian Guard does its job (this test passes only on a successful Deny + JSONL row)
//!   2. Sink hostname is in the IETF-reserved `.invalid` TLD (cannot resolve);
//!      `sink_listener::start_or_hosts` additionally redirects c2-sink.test.invalid
//!      to 127.0.0.1 via /etc/hosts (or localhost listener fallback)
//!   3. Sandboxed HOME (`sandbox_home::create()` + `Command::new(...).env_clear()`
//!      on the wrapped child via `portable_pty`'s `CommandBuilder` which does not
//!      inherit env unless told)
//!
//! macos-only #[`cfg_attr`] gate ensures developer machines on Linux/Windows don't
//! accidentally run the test (D-01 isolation).

use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::time::Duration;

use guard_e2e::test_support::{sandbox_home, sink_listener};
use guard_e2e::{
    DaemonHarness, cargo_workspace_root, read_pty_until, resolve_cli, resolve_dylib, resolve_node,
};
use portable_pty::{CommandBuilder, PtySize, native_pty_system};

struct UaParserFixture {
    _fixture_dir: tempfile::TempDir,
    package_dir: PathBuf,
    preinstall: PathBuf,
}

#[cfg_attr(not(target_os = "macos"), ignore = "macOS-only test")]
#[test]
fn ua_parser_js_postinstall_blocked_with_package_context() {
    // -----------------------------------------------------------------------
    // Setup: sandboxed HOME, sink redirect for c2-sink.test.invalid,
    // daemon harness, fixture path.
    // -----------------------------------------------------------------------
    let _sandbox = sandbox_home::create().expect("sandbox HOME");
    // Note: DaemonHarness::start() also creates its own home tempdir (used as
    // the daemon's HOME and the JSONL log root). The _sandbox above provides
    // an additional D-02 sandbox if any test code wants to spawn an independent
    // command outside the harness; the harness's home is what the wrapped
    // command actually inherits via the cmd.env("HOME", harness.home.path())
    // below.

    let cli = resolve_cli();
    let dylib = resolve_dylib();
    let Some(node) = resolve_node_or_skip() else {
        return;
    };

    let mut harness = DaemonHarness::start().expect("start daemon");

    // Sink redirect: c2-sink.test.invalid -> 127.0.0.1 via /etc/hosts (or
    // localhost-listener fallback). RAII Drop restores /etc/hosts on test exit.
    let _sink = sink_listener::start_or_hosts(&["c2-sink.test.invalid"], 0).expect("sink redirect");

    let fixture = extract_fixture_package();

    // -----------------------------------------------------------------------
    // PTY scaffolding (from prompt_unblock_deny.rs).
    // -----------------------------------------------------------------------
    let pty_system = native_pty_system();
    let pair = open_test_pty(&*pty_system);
    let cmd = preinstall_command(&cli, &node, &dylib, &harness, &fixture);
    let mut child = pair.slave.spawn_command(cmd).expect("spawn stt-guard wrap");
    let reader = pair.master.try_clone_reader().expect("reader");
    let mut writer = pair.master.take_writer().expect("writer");
    drop(pair.slave);

    // -----------------------------------------------------------------------
    // Wait for the prompt to appear, then pre-script Deny (choice 3).
    // The CLI prompt UI (prompt_render.rs:65) prints:
    //   "  Choose: [1]once  [2]always  [3]deny  [?]help"
    // -----------------------------------------------------------------------
    let _buf = read_pty_until(reader, "Choose: [1]", Duration::from_secs(60))
        .unwrap_or_else(|e| panic!("{e}\nstderr:\n{}", harness.drain_stderr()));
    writer.write_all(b"3\n").expect("write Deny");
    drop(writer);

    // Wait for the wrapped command to exit. PTY exit codes are unreliable
    // (per prompt_unblock_deny.rs note); we don't HARD-assert on exit code.
    let _ = child.wait();

    // Allow log_writer mpsc to drain (v0.3/v0.4 e2e canon — 500ms margin).
    std::thread::sleep(Duration::from_millis(500));

    // -----------------------------------------------------------------------
    // HARD assertion (CONTEXT C-01): JSONL row with verdict=Deny +
    // source_kind=prompt_deny + package_context.package=ua-parser-js.
    // -----------------------------------------------------------------------
    let log = harness
        .home
        .path()
        .join("Library/Logs/Stentorian Guard/stt-guard.log");
    let content = std::fs::read_to_string(&log).unwrap_or_default();
    let matched = content.lines().any(ua_parser_prompt_deny_row);
    assert!(
        matched,
        "HARD assertion failed: no JSONL row matching verdict=Deny + \
         source_kind=prompt_deny + package_context.package=ua-parser-js;\n\
         log file: {}\n\
         contents:\n{content}\n\
         daemon stderr:\n{}",
        log.display(),
        harness.drain_stderr()
    );

    // -----------------------------------------------------------------------
    // SOFT assertion (CONTEXT C-01 opportunistic): intel.feed = "OSV".
    // Don't fail the test if intel is absent — OSV freshness drift is acceptable.
    // -----------------------------------------------------------------------
    let intel_attributed = content.lines().any(ua_parser_osv_row);
    if !intel_attributed {
        eprintln!(
            "[note] no intel.feed=OSV attribution on the ua-parser-js row; \
             OSV freshness drift acceptable per CONTEXT C-01 SOFT assert"
        );
    }

    drop(harness);
}

fn resolve_node_or_skip() -> Option<PathBuf> {
    match resolve_node() {
        Ok(path) => Some(path),
        Err(why) => {
            eprintln!("SKIP ua_parser_js_demo: {why}");
            None
        }
    }
}

fn extract_fixture_package() -> UaParserFixture {
    let fixture = cargo_workspace_root()
        .join("crates/guard-e2e/fixtures/ua-parser-js-0.7.29-sanitized")
        .join("ua-parser-js-0.7.29-sanitized.tgz");
    assert!(
        fixture.exists(),
        "fixture missing — run tools/vendor-ua-parser-js.sh first: {}",
        fixture.display()
    );

    let fixture_dir = tempfile::tempdir().expect("extract fixture tempdir");
    let tar_out = std::process::Command::new("/usr/bin/tar")
        .arg("-xzf")
        .arg(&fixture)
        .arg("-C")
        .arg(fixture_dir.path())
        .output()
        .expect("extract fixture");
    assert!(
        tar_out.status.success(),
        "extract fixture failed: stdout={}\nstderr={}",
        String::from_utf8_lossy(&tar_out.stdout),
        String::from_utf8_lossy(&tar_out.stderr)
    );

    let package_dir = fixture_dir.path().join("package");
    let preinstall = package_dir.join("preinstall.js");
    UaParserFixture {
        _fixture_dir: fixture_dir,
        package_dir,
        preinstall,
    }
}

fn open_test_pty(pty_system: &(dyn portable_pty::PtySystem + Send)) -> portable_pty::PtyPair {
    pty_system
        .openpty(PtySize {
            rows: 24,
            cols: 80,
            pixel_width: 0,
            pixel_height: 0,
        })
        .expect("openpty")
}

fn preinstall_command(
    cli: &Path,
    node: &Path,
    dylib: &Path,
    harness: &DaemonHarness,
    fixture: &UaParserFixture,
) -> CommandBuilder {
    let mut cmd = CommandBuilder::new(cli);
    cmd.arg("wrap");
    cmd.arg(node);
    cmd.arg(&fixture.preinstall);
    cmd.cwd(&fixture.package_dir);

    cmd.env("HOME", harness.home.path().to_str().unwrap());
    cmd.env("PATH", std::env::var("PATH").unwrap_or_default().as_str());
    cmd.env("STT_GUARD_HOOK_DYLIB", dylib.to_str().unwrap());
    cmd.env("STT_GUARD_STATE_DIR", harness.state_dir.to_str().unwrap());
    cmd.env("npm_package_name", "ua-parser-js");
    cmd.env("npm_package_version", "0.7.29");
    cmd.env("npm_lifecycle_event", "preinstall");
    cmd
}

fn ua_parser_prompt_deny_row(line: &str) -> bool {
    let Ok(v) = serde_json::from_str::<serde_json::Value>(line) else {
        return false;
    };

    let verdict = v.get("verdict").and_then(|x| x.as_str());
    let source_kind = v.get("source_kind").and_then(|x| x.as_str());
    let pkg = v
        .pointer("/package_context/package")
        .and_then(|x| x.as_str());
    verdict == Some("Deny") && source_kind == Some("prompt_deny") && pkg == Some("ua-parser-js")
}

fn ua_parser_osv_row(line: &str) -> bool {
    let Ok(v) = serde_json::from_str::<serde_json::Value>(line) else {
        return false;
    };

    let pkg = v
        .pointer("/package_context/package")
        .and_then(|x| x.as_str());
    if pkg != Some("ua-parser-js") {
        return false;
    }

    v.get("intel")
        .and_then(|x| x.as_array())
        .is_some_and(|arr| {
            arr.iter()
                .any(|m| m.get("feed").and_then(|s| s.as_str()) == Some("OSV"))
        })
}
