//! Phase 4 plan 04-03 (D-91 + D-93): enrich block-log Decision rows with
//! IntelMatch entries by querying `feed_iocs` at log-write time.
//!
//! Mirrors `package_context.rs` shape — pure function called from IPC handler
//! context, NOT the writer thread (Phase 3 D-54 caller-side discipline). The
//! caller passes the result to `Decision { intel: Some(matches), ... }` (or
//! `intel: None` when the returned vec is empty, per Phase 3 D-56
//! omit-when-empty convention).
//!
//! Two entry points:
//!   - `enrich(feed_store, package_context)` — the primary D-91 path. Looks
//!     up rows by (ecosystem, package), then filters by `versions_json` via
//!     `osv_match::version_in_affected_block`. Each match is `source: "package"`.
//!   - `enrich_for_host(feed_store, host)` — the D-90 host-source path. Used
//!     when a block fired because the destination host matched a feed
//!     `host_ioc` row. Each match is `source: "host"`.

use sentinel_core::osv_match;
use sentinel_ipc::{IntelMatch, PackageContext};
use serde::Deserialize;

use crate::feed::store::FeedStore;

/// JSON shape of `feed_iocs.versions_json` per parser.rs: a `{"versions": [...],
/// "ranges": [...]}` subset of the OSV `affected[]` element. We deserialize on
/// demand (cheap — bounded by row count, typically 0..a few rows per
/// (ecosystem, package) pair) rather than at row-read time so the FeedStore
/// stays storage-shape only.
#[derive(Deserialize)]
struct AffectedShape {
    #[serde(default)]
    versions: Vec<String>,
    #[serde(default)]
    ranges: Vec<osv_match::Range>,
}

/// Returns matching `IntelMatch` entries for the given package_context.
/// Returns an empty Vec when (a) the context has empty ecosystem or package
/// fields, (b) the SQLite query fails (we warn and continue — feed enrichment
/// is best-effort, never blocks), or (c) no row's versions_json matches the
/// version per OSV semantics. Each match has `source = "package"`.
pub fn enrich(feed_store: &FeedStore, pkg: &PackageContext) -> Vec<IntelMatch> {
    if pkg.ecosystem.is_empty() || pkg.package.is_empty() {
        return Vec::new();
    }
    // TI-08 differentiation: emit on `sentinel.feed.enrich` (NOT
    // `sentinel.feed.fetch`) so the feed_no_per_query.rs e2e test can
    // distinguish enrichment SQLite reads (local cache; never an outbound
    // fetch) from the actual fetch path. The two events share no
    // common substring.
    tracing::debug!(
        target = "sentinel.feed.enrich",
        ecosystem = %pkg.ecosystem,
        package = %pkg.package,
        version = %pkg.version,
        "log enrichment query (local SQLite read; not a network fetch)",
    );
    let candidates = match feed_store.query_by_pkg(&pkg.ecosystem, &pkg.package) {
        Ok(v) => v,
        Err(e) => {
            tracing::warn!(error = %e, "log_writer enrichment: feed_iocs query failed");
            return Vec::new();
        }
    };
    let mut out = Vec::with_capacity(candidates.len());
    for row in candidates {
        // Skip rows that are host-IoC denormalizations (host_ioc IS NOT NULL).
        // Those rows live in feed_iocs only to be queryable via host_iocs();
        // their (ecosystem, package) tuple is either synthetic empty (host-
        // only advisory) or the same tuple as a sibling package row that
        // already appears in `candidates`. Counting them as package matches
        // would double-count and pollute the intel array.
        if row.host_ioc.is_some() {
            continue;
        }
        let affected: AffectedShape = match serde_json::from_str(&row.versions_json) {
            Ok(a) => a,
            Err(_) => continue,
        };
        if !pkg.version.is_empty()
            && !osv_match::version_in_affected_block(
                &pkg.version,
                &affected.versions,
                &affected.ranges,
            )
        {
            continue;
        }
        out.push(IntelMatch {
            feed: row.feed,
            advisory_id: row.advisory_id,
            source: "package".to_string(),
            severity: row.severity,
            tag: row.tag,
            first_seen_ms: row.first_seen_ms as u64,
        });
    }
    out
}

/// D-90 / D-93 variant: when a block fired because the destination host
/// equals a feed `host_ioc`, populate the host-source intel even when the
/// package_context is None. Returns an empty Vec when (a) host is empty or
/// (b) the SQLite query fails.
pub fn enrich_for_host(feed_store: &FeedStore, host: &str) -> Vec<IntelMatch> {
    if host.is_empty() {
        return Vec::new();
    }
    let rows = match feed_store.host_iocs() {
        Ok(v) => v,
        Err(e) => {
            tracing::warn!(error = %e, "log_writer enrichment: host_iocs query failed");
            return Vec::new();
        }
    };
    rows.into_iter()
        .filter(|r| r.host_ioc.as_deref() == Some(host))
        .map(|r| IntelMatch {
            feed: r.feed,
            advisory_id: r.advisory_id,
            source: "host".to_string(),
            severity: r.severity,
            tag: r.tag,
            first_seen_ms: r.first_seen_ms as u64,
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::feed::store::FeedIocRow;

    fn pkg_row(advisory: &str, ecosystem: &str, package: &str, versions_json: &str) -> FeedIocRow {
        FeedIocRow {
            feed: "OSV".to_string(),
            advisory_id: advisory.to_string(),
            ecosystem: ecosystem.to_string(),
            package: package.to_string(),
            versions_json: versions_json.to_string(),
            severity: Some("HIGH".to_string()),
            tag: Some("malicious".to_string()),
            first_seen_ms: 1_700_000_000_000,
            host_ioc: None,
            schema_version_observed: "1.7.4".to_string(),
        }
    }

    fn host_row(advisory: &str, host: &str) -> FeedIocRow {
        FeedIocRow {
            feed: "OSV".to_string(),
            advisory_id: advisory.to_string(),
            ecosystem: String::new(),
            package: String::new(),
            versions_json: "{\"versions\":[],\"ranges\":[]}".to_string(),
            severity: Some("CRITICAL".to_string()),
            tag: Some("c2".to_string()),
            first_seen_ms: 1_700_000_000_001,
            host_ioc: Some(host.to_string()),
            schema_version_observed: "1.7.4".to_string(),
        }
    }

    fn pkg_ctx(ecosystem: &str, package: &str, version: &str) -> PackageContext {
        PackageContext {
            ecosystem: ecosystem.to_string(),
            package: package.to_string(),
            version: version.to_string(),
            lifecycle: None,
            root_command: String::new(),
        }
    }

    #[test]
    fn enrich_returns_empty_when_ecosystem_or_package_blank() {
        let store = FeedStore::open_in_memory().unwrap();
        store
            .upsert_iocs(&[pkg_row(
                "MAL-A",
                "npm",
                "lodash",
                r#"{"versions":["1.0.0"],"ranges":[]}"#,
            )])
            .unwrap();

        let blank_eco = enrich(&store, &pkg_ctx("", "lodash", "1.0.0"));
        assert!(blank_eco.is_empty());

        let blank_pkg = enrich(&store, &pkg_ctx("npm", "", "1.0.0"));
        assert!(blank_pkg.is_empty());
    }

    #[test]
    fn enrich_query_filters_by_version_match() {
        // 3 rows for npm/lodash. Two cover [1.0.0, 2.0.0); one covers
        // [2.0.0, 3.0.0). Calling enrich with "1.5.0" should return 2 matches;
        // "2.5.0" should return 1.
        let store = FeedStore::open_in_memory().unwrap();
        let r1 = pkg_row(
            "MAL-1",
            "npm",
            "lodash",
            r#"{"versions":[],"ranges":[{"type":"SEMVER","events":[{"introduced":"1.0.0"},{"fixed":"2.0.0"}]}]}"#,
        );
        let r2 = pkg_row(
            "MAL-2",
            "npm",
            "lodash",
            r#"{"versions":[],"ranges":[{"type":"SEMVER","events":[{"introduced":"1.0.0"},{"fixed":"2.0.0"}]}]}"#,
        );
        let r3 = pkg_row(
            "MAL-3",
            "npm",
            "lodash",
            r#"{"versions":[],"ranges":[{"type":"SEMVER","events":[{"introduced":"2.0.0"},{"fixed":"3.0.0"}]}]}"#,
        );
        store.upsert_iocs(&[r1, r2, r3]).unwrap();

        let matches = enrich(&store, &pkg_ctx("npm", "lodash", "1.5.0"));
        assert_eq!(matches.len(), 2);
        let ids: Vec<&str> = matches.iter().map(|m| m.advisory_id.as_str()).collect();
        assert!(ids.contains(&"MAL-1"));
        assert!(ids.contains(&"MAL-2"));

        let matches2 = enrich(&store, &pkg_ctx("npm", "lodash", "2.5.0"));
        assert_eq!(matches2.len(), 1);
        assert_eq!(matches2[0].advisory_id, "MAL-3");
    }

    #[test]
    fn enrich_advisory_metadata_propagates_with_source_package() {
        let store = FeedStore::open_in_memory().unwrap();
        store
            .upsert_iocs(&[pkg_row(
                "MAL-X",
                "npm",
                "evil-pkg",
                r#"{"versions":["1.0.0"],"ranges":[]}"#,
            )])
            .unwrap();

        let matches = enrich(&store, &pkg_ctx("npm", "evil-pkg", "1.0.0"));
        assert_eq!(matches.len(), 1);
        let m = &matches[0];
        assert_eq!(m.feed, "OSV");
        assert_eq!(m.advisory_id, "MAL-X");
        assert_eq!(m.source, "package");
        assert_eq!(m.severity.as_deref(), Some("HIGH"));
        assert_eq!(m.tag.as_deref(), Some("malicious"));
        assert_eq!(m.first_seen_ms, 1_700_000_000_000);
    }

    #[test]
    fn enrich_skips_host_only_rows() {
        // A row with host_ioc=Some(...) and the same (ecosystem, package)
        // should be skipped — host-source enrichment goes through
        // enrich_for_host, not the package path.
        let store = FeedStore::open_in_memory().unwrap();
        let mut hr = pkg_row(
            "MAL-HOST",
            "npm",
            "evil-pkg",
            r#"{"versions":["1.0.0"],"ranges":[]}"#,
        );
        hr.host_ioc = Some("evil.example.com".into());
        let pr = pkg_row(
            "MAL-PKG",
            "npm",
            "evil-pkg",
            r#"{"versions":["1.0.0"],"ranges":[]}"#,
        );
        store.upsert_iocs(&[hr, pr]).unwrap();

        let matches = enrich(&store, &pkg_ctx("npm", "evil-pkg", "1.0.0"));
        assert_eq!(matches.len(), 1, "host-IoC row should be skipped");
        assert_eq!(matches[0].advisory_id, "MAL-PKG");
    }

    #[test]
    fn enrich_for_host_returns_matches_with_source_host() {
        let store = FeedStore::open_in_memory().unwrap();
        store
            .upsert_iocs(&[
                host_row("MAL-A", "evil.example.com"),
                host_row("MAL-B", "other.example.com"),
            ])
            .unwrap();

        let matches = enrich_for_host(&store, "evil.example.com");
        assert_eq!(matches.len(), 1);
        let m = &matches[0];
        assert_eq!(m.advisory_id, "MAL-A");
        assert_eq!(m.source, "host");
        assert_eq!(m.severity.as_deref(), Some("CRITICAL"));
        assert_eq!(m.tag.as_deref(), Some("c2"));
    }

    #[test]
    fn enrich_for_host_returns_empty_for_blank_host() {
        let store = FeedStore::open_in_memory().unwrap();
        store
            .upsert_iocs(&[host_row("MAL-A", "evil.example.com")])
            .unwrap();
        let matches = enrich_for_host(&store, "");
        assert!(matches.is_empty());
    }

    #[test]
    fn enrich_versionless_pkg_context_falls_back_to_match() {
        // When pkg.version is empty (rare — Phase 3 D-53 guarantees it's
        // populated when ecosystem+package are), we currently return all
        // package rows for that (ecosystem, package). Regression-pin the
        // behavior: empty version is permissive, NOT exclusive.
        let store = FeedStore::open_in_memory().unwrap();
        store
            .upsert_iocs(&[pkg_row(
                "MAL-V",
                "npm",
                "no-version",
                r#"{"versions":["1.0.0"],"ranges":[]}"#,
            )])
            .unwrap();
        let matches = enrich(&store, &pkg_ctx("npm", "no-version", ""));
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].advisory_id, "MAL-V");
    }
}
