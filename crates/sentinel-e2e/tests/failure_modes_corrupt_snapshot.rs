//! Phase 5 plan 05-05 — VAL-04 D-12: corrupt-snapshot failure mode.
//!
//! Verifies the dylib's "fail closed for tracked subtrees on snapshot decode
//! failure" contract.
//!
//! Approach: write garbage bytes into a manifest+snapshot pair the test owns,
//! then directly spawn `node -e "<probe>"` with `DYLD_INSERT_LIBRARIES=$dylib` +
//! `SENTINEL_SNAPSHOT_MANIFEST=$corrupt_manifest`. We BYPASS `sentinel run`
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
    // (the canonical per-run snapshot location). Per Phase 02-06a layout:
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
    // BYPASS `sentinel run` per RESEARCH §A1 — spawn_wrapped strips and
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
    // dylib's FAIL_CLOSED interceptor returning -1. To distinguish
    // \"fail-closed engaged\" from \"unrelated network failure\" we require:
    //
    //   (1) node exited non-zero AND printed \"DENIED:\" — proves the
    //       connect failed AND the failure path fired before the 4s
    //       timeout (TIMEOUT exits with code 2; LEAKED with code 0).
    //   (2) The error code (after \"DENIED:\") looks like a connect-layer
    //       deny rather than a DNS-resolution failure. The dylib's libc
    //       interceptor returns -1 with EHOSTUNREACH / ECONNREFUSED /
    //       EPERM / ENETUNREACH; node maps those to e.code values like
    //       \"EHOSTUNREACH\", \"ECONNREFUSED\", \"EPERM\", \"ENETUNREACH\".
    //       A DNS failure surfaces as \"ENOTFOUND\" or \"EAI_AGAIN\" — those
    //       are genuine network problems, not proof of fail-closed.
    //
    // If the dylib's FAIL_CLOSED ctor ever starts emitting an explicit
    // stderr marker (currently it only writes to an in-process LOG_RING),
    // tighten further to grep for that marker. Today the connect-error-code
    // shape is the strongest signal available without changing the dylib.
    assert!(
        !out.status.success() && stdout.contains("DENIED"),
        "VAL-04 D-12 HARD assertion failed: node did NOT fail-closed under corrupt snapshot.\n\
         exit: {:?}\n\
         stdout: {stdout}\n\
         stderr: {stderr}",
        out.status.code(),
    );
    let denied_line = stdout
        .lines()
        .find(|l| l.contains("DENIED:"))
        .expect("DENIED line present per assertion above");
    let connect_layer_codes = [
        "EHOSTUNREACH",
        "ECONNREFUSED",
        "EPERM",
        "ENETUNREACH",
        "EACCES",
    ];
    let dns_codes = ["ENOTFOUND", "EAI_AGAIN", "EAI_NONAME"];
    let is_connect_layer = connect_layer_codes
        .iter()
        .any(|c| denied_line.contains(c));
    let is_dns = dns_codes.iter().any(|c| denied_line.contains(c));
    assert!(
        is_connect_layer && !is_dns,
        "VAL-04 D-12 WR-06 HARD assertion failed: node printed DENIED but the error \
         code does not match a connect-layer fail-closed shape. Could be unrelated \
         network failure rather than the dylib's interceptor.\n\
         denied line: {denied_line}\n\
         expected one of: {connect_layer_codes:?}\n\
         must NOT match: {dns_codes:?}\n\
         full stdout: {stdout}\n\
         stderr: {stderr}",
    );

    drop(harness);
}
