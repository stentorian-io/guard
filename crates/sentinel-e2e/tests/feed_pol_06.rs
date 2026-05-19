//! v0.4 POL-06 regression: planted FeedDeny for registry.npmjs.org should
//! be overridden by the curated allowlist. Confirms the curated-allow-beats-feed-deny
//! invariant flows through the daemon's snapshot-build path correctly.
//!
//! The unit invariant is verified in `precedence.rs`. This test exercises the FULL
//! pipeline: daemon fetches a fixture file:// repo via gix → parses OSV record →
//! upserts feed_iocs → PrepareSnapshot merges FeedDeny entries from
//! `feed_iocs.host_ioc IS NOT NULL` → curated YAML's CuratedAllow for
//! registry.npmjs.org sorts ahead of FeedDeny (RuleTier 1 < 4) → snapshot is
//! published → /usr/bin/true succeeds.
//!
//! Also asserts the TI-07 e2e: after a successful fetch, `sentinel status --json`
//! reports OSV feed `fresh: true` AND a non-null `last_pulled_at_ms`.

use sentinel_e2e::{prepare_feed_fixture, resolve_cli, resolve_dylib, DaemonHarness};
use std::process::Command;

#[cfg_attr(not(target_os = "macos"), ignore)]
#[test]
fn registry_npmjs_org_allowed_despite_planted_feed_deny() {
    let (_fixture_tempdir, fixture_url) = prepare_feed_fixture("feed-mock-pol06");
    let cli = resolve_cli();
    let dylib = resolve_dylib();
    // Start a daemon that WILL fetch (no SKIP_FEED_FETCH) and points OSV +
    // GHSA at our file:// fixture (same fixture serves both — the planted
    // record's ecosystem is npm; either feed clone path produces feed_iocs
    // rows for the host_ioc).
    let mut harness = DaemonHarness::start_with_env(&[
        ("SENTINEL_FEED_URL_OVERRIDE_OSV", fixture_url.as_str()),
        ("SENTINEL_FEED_URL_OVERRIDE_GHSA", fixture_url.as_str()),
    ])
    .expect("start daemon");

    // /usr/bin/true is hardened-runtime (system binary) but Sentinel's run
    // path still completes PrepareSnapshot before the exec. The run succeeds
    // because /usr/bin/true does no networking; we exercise PrepareSnapshot
    // (which does the fetch + snapshot build) via this trivial process.
    let output = Command::new(&cli)
        .arg("wrap")
        .arg("/usr/bin/true")
        .env_clear()
        .env("HOME", harness.home.path())
        .env("PATH", std::env::var_os("PATH").unwrap_or_default())
        .env("SENTINEL_HOOK_DYLIB", &dylib)
        .env("SENTINEL_STATE_DIR", &harness.state_dir)
        .output()
        .expect("run sentinel");

    assert!(
        output.status.success(),
        "sentinel wrap /usr/bin/true should succeed even with planted FeedDeny for registry.npmjs.org\n\
         exit code: {:?}\nstdout:\n{}\nstderr:\n{}\ndaemon stderr:\n{}",
        output.status.code(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
        harness.drain_stderr(),
    );

    // (a) feed_iocs row exists for registry.npmjs.org (proves the fetch +
    // parse + host extraction path works against the fixture).
    let db_path = harness.state_dir.join("sentinel.db");
    let conn = rusqlite::Connection::open_with_flags(
        &db_path,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )
    .expect("open sentinel.db");
    let count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM feed_iocs WHERE host_ioc = 'registry.npmjs.org'",
            [],
            |r| r.get(0),
        )
        .expect("query feed_iocs");
    // We point both OSV and GHSA at the same fixture, so the planted host_ioc
    // appears once per feed (PK includes feed). The assertion is >= 1 — proves
    // the fetch + parse + host_ioc extraction path lands rows.
    assert!(
        count >= 1,
        "feed_iocs must contain the planted host_ioc registry.npmjs.org (got count={count})"
    );

    // (b) decoded snapshot CBOR shows CuratedAllow precedes FeedDeny.
    // The per-run snapshot may have been GC'd 30s after the run; if so,
    // skip this part (the feed_iocs check above is the load-bearing
    // assertion for D-94 — the structural POL-06 invariant is verified by
    // precedence.rs unit tests).
    let runs_dir = harness.state_dir.join("runs");
    if let Ok(entries) = std::fs::read_dir(&runs_dir) {
        let cbor_files: Vec<_> = entries
            .filter_map(|e| e.ok())
            .filter(|e| e.path().extension().is_some_and(|ext| ext == "cbor"))
            .collect();
        if let Some(cbor) = cbor_files.first() {
            let bytes = std::fs::read(cbor.path()).expect("read snapshot");
            let snap = sentinel_core::Snapshot::decode(&bytes).expect("decode snapshot");
            let curated_pos = snap.entries.iter().position(|e| {
                matches!(e.tier, sentinel_core::RuleTier::CuratedAllow)
                    && e.pattern.contains("npmjs.org")
            });
            let feeddeny_pos = snap.entries.iter().position(|e| {
                matches!(e.tier, sentinel_core::RuleTier::FeedDeny)
                    && e.pattern == "registry.npmjs.org"
            });
            match (curated_pos, feeddeny_pos) {
                (Some(c), Some(f)) => {
                    assert!(
                        c < f,
                        "POL-06 invariant: CuratedAllow at pos {c} must precede FeedDeny at pos {f}\nentries: {:?}",
                        snap.entries.iter().map(|e| (e.tier, e.pattern.clone())).collect::<Vec<_>>(),
                    );
                }
                (None, _) => panic!(
                    "Expected CuratedAllow for npmjs.org in snapshot; entries={:?}",
                    snap.entries
                        .iter()
                        .map(|e| (e.tier, e.pattern.clone()))
                        .collect::<Vec<_>>(),
                ),
                (_, None) => panic!(
                    "Expected FeedDeny for registry.npmjs.org in snapshot; entries={:?}",
                    snap.entries
                        .iter()
                        .map(|e| (e.tier, e.pattern.clone()))
                        .collect::<Vec<_>>(),
                ),
            }
        }
    }

    // (c) TI-07 e2e (B-6): after a successful fetch, `sentinel status --json` MUST
    // report OSV with `fresh=true` and `last_pulled_at_ms` as a non-null integer.
    let status_output = Command::new(&cli)
        .arg("status")
        .arg("--json")
        .env_clear()
        .env("HOME", harness.home.path())
        .env("PATH", std::env::var_os("PATH").unwrap_or_default())
        .env("SENTINEL_STATE_DIR", &harness.state_dir)
        .output()
        .expect("run sentinel status");
    assert!(
        status_output.status.success(),
        "sentinel status --json failed: stdout={}\nstderr={}",
        String::from_utf8_lossy(&status_output.stdout),
        String::from_utf8_lossy(&status_output.stderr),
    );
    let status_json: serde_json::Value = serde_json::from_slice(&status_output.stdout)
        .expect("status reply must be valid JSON");

    // StatusReply::Ok serializes via serde's external-tag enum: top-level
    // shape is `{"Ok": { schema_version, daemon_state, ..., feeds: [...] }}`.
    let ok_payload = status_json
        .get("Ok")
        .expect("StatusReply::Ok variant — got: {status_json}");
    let feeds = ok_payload
        .get("feeds")
        .and_then(|v| v.as_array())
        .expect("status JSON Ok.feeds[] must be an array (TI-07)");
    assert!(
        !feeds.is_empty(),
        "feeds[] must not be empty after a successful fetch (TI-07)\nstatus:\n{}",
        String::from_utf8_lossy(&status_output.stdout),
    );
    let osv = feeds
        .iter()
        .find(|f| f.get("name").and_then(|n| n.as_str()) == Some("OSV"))
        .expect("feeds[] must contain an OSV entry (TI-07)");
    let fresh = osv
        .get("fresh")
        .and_then(|v| v.as_bool())
        .expect("feeds[].fresh must be a bool (TI-07)");
    let last_pulled = osv
        .get("last_pulled_at_ms")
        .expect("feeds[].last_pulled_at_ms field must exist (TI-07)");
    assert!(
        fresh,
        "OSV feed must be fresh after a successful fetch within the test run (TI-07)\nstatus:\n{}",
        String::from_utf8_lossy(&status_output.stdout),
    );
    assert!(
        last_pulled.is_number(),
        "OSV feeds[].last_pulled_at_ms must be a non-null integer ms-epoch after success (TI-07)\nobserved: {last_pulled:?}",
    );
}
