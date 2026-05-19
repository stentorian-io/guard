//! v0.5 — corrupt-snapshot failure mode.
//!
//! Verifies the dylib's "fail closed for tracked subtrees on snapshot decode
//! failure" contract.
//!
//! Approach: write garbage bytes into a manifest+snapshot pair the test owns,
//! then directly spawn `node -e "<probe>"` with `DYLD_INSERT_LIBRARIES=$dylib` +
//! `SENTINEL_SNAPSHOT_MANIFEST=$corrupt_manifest`. We BYPASS `sentinel wrap`
//! because `crates/sentinel-cli/src/spawn.rs:38` strips and re-sets the
//! manifest envp unconditionally (RESEARCH §A1 verified at plan time). We use
//! node (not curl) because curl is hardened-runtime on macos-14 and would
//! strip DYLD_INSERT_LIBRARIES on exec — the dylib would never load and the
//! test would silently no-op. Node from setup-node@v4 is non-hardened
//! (RESEARCH §A4) so DYLD injection is honored at node ctor.
//!
//! The dylib's snapshot::load_from_env returns LoadError::Codec, sets
//! FAIL_CLOSED=true, and every subsequent connect denies. node observes
//! the connect failure and prints DENIED.

use std::process::Command;

use sentinel_e2e::{resolve_dylib, resolve_node, DaemonHarness};

#[cfg_attr(not(target_os = "macos"), ignore)]
#[test]
fn corrupt_snapshot_causes_dylib_to_fail_closed() {
    let dylib = resolve_dylib();
    let node = match resolve_node() {
        Ok(p) => p,
        Err(why) => {
            eprintln!("SKIP corrupt_snapshot: {why}");
            return;
        }
    };
    // We DO need a daemon harness to provide a state_dir under which we plant
    // the corrupt manifest+snapshot files; the daemon itself doesn't need to
    // serve any IPC for this test (the dylib fails closed before any
    // send_*_sync fires).
    let harness = DaemonHarness::start().expect("start daemon");

    // Build the corrupt manifest+snapshot pair under harness.state_dir/runs/
    // (the canonical per-run snapshot location). Layout:
    //   runs/<uuid>.cbor
    //   runs/<uuid>.manifest   (line 1 = abs path; line 2 = digest=<hex>)
    let runs_dir = harness.state_dir.join("runs");
    std::fs::create_dir_all(&runs_dir).expect("ensure runs dir");
    let snap_path = runs_dir.join("corrupt-test.cbor");
    let manifest_path = runs_dir.join("corrupt-test.manifest");

    // Garbage bytes — definitely not valid CBOR. The dylib's Snapshot::decode
    // is a pure deserializer; any non-CBOR sequence fails with Codec error.
    let garbage = b"GARBAGE_NOT_CBOR_AT_ALL_PLAN_05_05";
    std::fs::write(&snap_path, garbage).expect("write garbage snapshot");

    // Manifest digest matches the garbage (so DigestMismatch is NOT the trip
    // path; we want LoadError::Codec to fire). The digest_hex is the SHA-256
    // of the garbage bytes. Manifest format = `{snapshot_path}\ndigest={hex}\n`
    // per crates/sentinel-hook/tests/snapshot_loader_tests.rs.
    use sha2::{Digest, Sha256};
    let digest_hex = format!("{:x}", Sha256::digest(garbage));
    let manifest_content = format!(
        "{}\ndigest={}\n",
        snap_path.display(),
        digest_hex,
    );
    std::fs::write(&manifest_path, manifest_content).expect("write manifest");

    // Spawn node directly with DYLD_INSERT_LIBRARIES + manifest envp injected.
    // BYPASS `sentinel wrap` per RESEARCH §A1 — spawn_wrapped strips and
    // re-sets SENTINEL_SNAPSHOT_MANIFEST, so we cannot inject the corrupt
    // manifest through the CLI orchestrator.
    //
    // SENTINEL_STATE_DIR is set so the dylib's `well_known_state_dir()` path
    // validator (snapshot.rs:54) accepts the manifest path under
    // /tmp/.se2eXXX/runs/. Without this override, the dylib would fall back to
    // HOME-derivation ($HOME/Library/Application Support/Sentinel) and reject
    // the manifest with PathOutsideStateDir before reaching the CBOR decode
    // step — also fail-closed, but for the wrong reason. Setting STATE_DIR
    // ensures we exercise the LoadError::Codec path specifically.
    //
    // The dylib loads at node's ctor → reads SENTINEL_SNAPSHOT_MANIFEST →
    // reads the manifest line → reads snap_path bytes → SHA-256 matches →
    // tries to CBOR-decode garbage → LoadError::Codec → FAIL_CLOSED=true →
    // every libc::connect interceptor returns -1 → node's net.connect
    // fires its 'error' handler and prints DENIED.
    let probe = "const net = require('net'); \
                 const c = net.connect(443, 'registry.npmjs.org'); \
                 c.on('connect', () => { console.log('LEAKED'); process.exit(0); }); \
                 c.on('error', e => { console.log('DENIED:', e.code); process.exit(1); }); \
                 setTimeout(() => { console.log('TIMEOUT'); process.exit(2); }, 4000);";
    let out = Command::new(&node)
        .arg("-e")
        .arg(probe)
        .env_clear()
        .env("HOME", harness.home.path())
        .env("PATH", std::env::var_os("PATH").unwrap_or_default())
        .env("DYLD_INSERT_LIBRARIES", &dylib)
        .env("SENTINEL_SNAPSHOT_MANIFEST", &manifest_path)
        .env("SENTINEL_STATE_DIR", &harness.state_dir)
        // Intentionally NOT setting SENTINEL_DAEMON_SOCKET — the dylib's
        // FAIL_CLOSED logic fires at ctor before any IPC is needed.
        .output()
        .expect("spawn node");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);

    // WR-06: tighten the assertion. Previously the test only checked that
    // node printed \"DENIED\" — but \"DENIED:\" can fire on ANY connect error
    // (DNS failure, transient network blip, OS pressure), not just on the
    // dylib's FAIL_CLOSED interceptor. To distinguish "fail-closed engaged"
    // from "unrelated network failure" we require:
    //
    //   (1) node exited non-zero AND printed \"DENIED:\" — proves the
    //       connection failed before the 4s timeout.
    //   (2) The error code matches a fail-closed shape at either layer:
    //       - getaddrinfo interpose: EAI_FAIL (M005 — fires first for
    //         hostname-based connections when FAIL_CLOSED=true)
    //       - connect interpose: EHOSTUNREACH / ECONNREFUSED / EPERM /
    //         ENETUNREACH / EACCES
    //       Transient DNS codes (EAI_AGAIN, EAI_NONAME) are NOT valid
    //       fail-closed evidence — they indicate retry-able DNS errors.
    assert!(
        !out.status.success() && stdout.contains("DENIED"),
        "HARD assertion failed: node did NOT fail-closed under corrupt snapshot.\n\
         exit: {:?}\n\
         stdout: {stdout}\n\
         stderr: {stderr}",
        out.status.code(),
    );
    let denied_line = stdout
        .lines()
        .find(|l| l.contains("DENIED:"))
        .expect("DENIED line present per assertion above");
    // M005: FAIL_CLOSED can fire at two layers:
    //   - getaddrinfo interpose → returns EAI_FAIL (Node surfaces as "EAI_FAIL")
    //   - connect interpose → returns EHOSTUNREACH/ECONNREFUSED/EPERM/etc.
    // Both are valid fail-closed evidence. With M005's getaddrinfo interpose,
    // hostname-based connections hit getaddrinfo first and see EAI_FAIL.
    let fail_closed_codes = [
        "EHOSTUNREACH",
        "ECONNREFUSED",
        "EPERM",
        "ENETUNREACH",
        "EACCES",
        "EAI_FAIL",
    ];
    let dns_transient_codes = ["EAI_AGAIN", "EAI_NONAME"];
    let is_fail_closed = fail_closed_codes
        .iter()
        .any(|c| denied_line.contains(c));
    let is_transient_dns = dns_transient_codes.iter().any(|c| denied_line.contains(c));
    assert!(
        is_fail_closed && !is_transient_dns,
        "HARD assertion failed: node printed DENIED but the error \
         code does not match a fail-closed shape (connect-layer or getaddrinfo-layer). \
         Could be unrelated network failure rather than the dylib's interceptor.\n\
         denied line: {denied_line}\n\
         expected one of: {fail_closed_codes:?}\n\
         must NOT match: {dns_transient_codes:?}\n\
         full stdout: {stdout}\n\
         stderr: {stderr}",
    );

    drop(harness);
}
