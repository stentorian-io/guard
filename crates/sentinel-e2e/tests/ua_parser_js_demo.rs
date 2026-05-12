//! Phase 5 plan 05-04 — VAL-01: ua-parser-js@0.7.29 supply-chain CVE reproduction.
//!
//! Drives `sentinel run npm install ./fixtures/ua-parser-js-0.7.29-sanitized.tgz`
//! through a PTY so the daemon's prompt path fires (CONTEXT C-01: libc-deny path
//! does NOT emit JSONL today; prompt path is the only path that emits
//! Decision rows for outbound denies). Pre-scripts a Deny via writer.write_all,
//! then HARD-asserts on the JSONL Decision row.
//!
//! NOTE: per plan 05-01 (Rule 4 pivot under CONTEXT D-06 escape hatch), the
//! committed fixture is a SYNTHETIC MOCK — there are no real malicious bytes
//! in `ua-parser-js-0.7.29-sanitized.tgz`. The synthetic `preinstall.js`
//! unconditionally opens `net.createConnection({host: 'c2-sink.test.invalid',
//! port: 443})`, which is the only behavior VAL-01 asserts on. The C-01
//! HARD-assertion contract (verdict=Deny + source_kind=prompt_deny +
//! package_context.package="ua-parser-js") is preserved against this
//! synthetic shape since the .tgz still declares
//! `{"name":"ua-parser-js","version":"0.7.29"}` in its package.json.
//!
//! Triple-defense per CONTEXT D-02:
//!   1. Sentinel does its job (this test passes only on a successful Deny + JSONL row)
//!   2. Sink hostname is in the IETF-reserved `.invalid` TLD (cannot resolve);
//!      sink_listener::start_or_hosts additionally redirects c2-sink.test.invalid
//!      to 127.0.0.1 via /etc/hosts (or localhost listener fallback)
//!   3. Sandboxed HOME (sandbox_home::create() + Command::new(...).env_clear()
//!      on the wrapped child via portable_pty's CommandBuilder which does not
//!      inherit env unless told)
//!
//! macos-only #[cfg_attr] gate ensures developer machines on Linux/Windows don't
//! accidentally run the test (D-01 isolation).

use std::io::{BufRead, BufReader, Write as _};
use std::path::PathBuf;
use std::time::{Duration, Instant};

use portable_pty::{native_pty_system, CommandBuilder, PtySize};
use sentinel_e2e::test_support::{sandbox_home, sink_listener};
use sentinel_e2e::{
    cargo_workspace_root, prepare_feed_fixture, resolve_cli, resolve_dylib, DaemonHarness,
};

#[cfg_attr(not(target_os = "macos"), ignore)]
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

    // Use a local file:// feed fixture instead of DaemonHarness::start()'s
    // default SENTINEL_SKIP_FEED_FETCH=1 (which is compiled out in --release
    // builds, causing CI to attempt a real GitHub clone that times out).
    let (_feed_dir, feed_url) = prepare_feed_fixture("feed-mock-ua-parser-js");
    let mut harness = DaemonHarness::start_with_env(&[
        ("SENTINEL_FEED_URL_OVERRIDE_OSV", feed_url.as_str()),
        ("SENTINEL_FEED_URL_OVERRIDE_GHSA", feed_url.as_str()),
    ])
    .expect("start daemon");

    // Sink redirect: c2-sink.test.invalid -> 127.0.0.1 via /etc/hosts (or
    // localhost-listener fallback). RAII Drop restores /etc/hosts on test exit.
    let _sink = sink_listener::start_or_hosts(&["c2-sink.test.invalid"], 18443)
        .expect("sink redirect");

    // Locate the npm CLI. macos-14 GHA runner has Node 20.x via setup-node@v4
    // (non-hardened — RESEARCH §A4); fall back to /opt/homebrew/bin/npm if
    // PATH-resolution fails. The test skip-exits gracefully if npm is absent.
    let npm = match which_npm() {
        Some(p) => p,
        None => {
            eprintln!("npm not found on PATH; skipping ua_parser_js_demo (test requires npm)");
            return;
        }
    };

    // Fixture path (committed bytes from Plan 05-01).
    let fixture = cargo_workspace_root()
        .join("crates/sentinel-e2e/fixtures/ua-parser-js-0.7.29-sanitized")
        .join("ua-parser-js-0.7.29-sanitized.tgz");
    assert!(
        fixture.exists(),
        "VAL-01 fixture missing — run tools/vendor-ua-parser-js.sh first: {}",
        fixture.display()
    );

    // -----------------------------------------------------------------------
    // PTY scaffolding (from prompt_unblock_deny.rs).
    // -----------------------------------------------------------------------
    let pty_system = native_pty_system();
    let pair = pty_system
        .openpty(PtySize {
            rows: 24,
            cols: 80,
            pixel_width: 0,
            pixel_height: 0,
        })
        .expect("openpty");

    // Build CommandBuilder for `sentinel npm install file:./fixture.tgz`.
    let mut cmd = CommandBuilder::new(&cli);
    cmd.arg(&npm);
    cmd.arg("install");
    // npm honors local-path tarball install via the file: spec
    // (RESEARCH §A6). No --ignore-scripts flag — we WANT preinstall to fire
    // (it's the attack vector under test).
    cmd.arg(format!("file:{}", fixture.display()));

    // env_clear is implicit in CommandBuilder (it doesn't inherit unless told).
    // Set only what we need: HOME, PATH, SENTINEL_HOOK_DYLIB, SENTINEL_STATE_DIR.
    cmd.env("HOME", harness.home.path().to_str().unwrap());
    cmd.env("PATH", std::env::var("PATH").unwrap_or_default().as_str());
    cmd.env("SENTINEL_HOOK_DYLIB", dylib.to_str().unwrap());
    cmd.env("SENTINEL_STATE_DIR", harness.state_dir.to_str().unwrap());

    let mut child = pair.slave.spawn_command(cmd).expect("spawn sentinel run");
    let reader = pair.master.try_clone_reader().expect("reader");
    let mut writer = pair.master.take_writer().expect("writer");
    drop(pair.slave);

    // -----------------------------------------------------------------------
    // Wait for the prompt to appear, then pre-script Deny (choice 4).
    // The CLI prompt UI (prompt_render.rs:66) prints:
    //   "  Choose: [1]once  [2]always-machine  [3]always-project  [4]deny  [?]help"
    // We match on the unambiguous "Choose: [1]" prefix (matches every existing
    // PTY-driven e2e test in this crate).
    // -----------------------------------------------------------------------
    let mut br = BufReader::new(reader);
    let mut buf = String::new();
    let deadline = Instant::now() + Duration::from_secs(60); // npm install is slow on cold cache
    loop {
        if Instant::now() > deadline {
            panic!(
                "prompt never appeared within 60s; PTY buf:\n{buf}\nstderr:\n{}",
                harness.drain_stderr()
            );
        }
        let mut line = String::new();
        match br.read_line(&mut line) {
            Ok(0) | Err(_) => break,
            Ok(_) => {}
        }
        buf.push_str(&line);
        if buf.contains("Choose: [1]") || buf.contains("[d]eny") || buf.contains("Deny:") {
            break;
        }
    }
    // Choice "4" is the Deny option in the prompt UI (prompt_render.rs:66).
    // If the prompt UX changes, update this to match the current Deny shortcut.
    writer.write_all(b"4\n").expect("write Deny");
    drop(writer);

    // Wait for the wrapped command to exit. PTY exit codes are unreliable
    // (per prompt_unblock_deny.rs note); we don't HARD-assert on exit code.
    let _ = child.wait();

    // Allow log_writer mpsc to drain (Phase 3/4 e2e canon — 500ms margin).
    std::thread::sleep(Duration::from_millis(500));

    // -----------------------------------------------------------------------
    // HARD assertion (CONTEXT C-01): JSONL row with verdict=Deny +
    // source_kind=prompt_deny + package_context.package=ua-parser-js.
    // -----------------------------------------------------------------------
    let log = harness
        .home
        .path()
        .join("Library/Logs/Sentinel/sentinel.log");
    let content = std::fs::read_to_string(&log).unwrap_or_default();
    let matched = content.lines().any(|line| {
        let v: serde_json::Value = match serde_json::from_str(line) {
            Ok(v) => v,
            Err(_) => return false,
        };
        let verdict = v.get("verdict").and_then(|x| x.as_str());
        let source_kind = v.get("source_kind").and_then(|x| x.as_str());
        let pkg = v
            .pointer("/package_context/package")
            .and_then(|x| x.as_str());
        verdict == Some("Deny")
            && source_kind == Some("prompt_deny")
            && pkg == Some("ua-parser-js")
    });
    assert!(
        matched,
        "VAL-01 HARD assertion failed: no JSONL row matching verdict=Deny + \
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
    let intel_attributed = content.lines().any(|line| {
        let v: serde_json::Value = match serde_json::from_str(line) {
            Ok(v) => v,
            Err(_) => return false,
        };
        let pkg = v
            .pointer("/package_context/package")
            .and_then(|x| x.as_str());
        if pkg != Some("ua-parser-js") {
            return false;
        }
        match v.get("intel").and_then(|x| x.as_array()) {
            Some(arr) => arr
                .iter()
                .any(|m| m.get("feed").and_then(|s| s.as_str()) == Some("OSV")),
            None => false,
        }
    });
    if !intel_attributed {
        eprintln!(
            "[VAL-01 note] no intel.feed=OSV attribution on the ua-parser-js row; \
             OSV freshness drift acceptable per CONTEXT C-01 SOFT assert"
        );
    }

    drop(harness);
}

/// Locate npm via PATH; return None if not findable.
fn which_npm() -> Option<PathBuf> {
    if let Ok(out) = std::process::Command::new("/usr/bin/which").arg("npm").output() {
        if out.status.success() {
            let s = String::from_utf8_lossy(&out.stdout).trim().to_string();
            if !s.is_empty() {
                return Some(PathBuf::from(s));
            }
        }
    }
    // Fallbacks for GHA runner / Homebrew installs.
    for path in &["/opt/homebrew/bin/npm", "/usr/local/bin/npm"] {
        let p = PathBuf::from(path);
        if p.exists() {
            return Some(p);
        }
    }
    None
}
