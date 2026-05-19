//! v0.4: convert FeedStore host_iocs into AllowlistEntry FeedDeny entries
//! for the per-run snapshot. Pure transform — no I/O state, no shared mutable state —
//! so testable in isolation.
//!
//! Match-type heuristic (`classify_host`):
//!   - Pattern starts with `*.` → MatchType::Suffix (with the leading `*` stripped to `.`,
//!     producing the leading-dot pattern AllowlistEntry::matches expects)
//!   - Pattern parses as `IpAddr` → MatchType::Ip
//!   - Else → MatchType::Exact

use sentinel_core::{AllowlistEntry, MatchType, RuleKind, RuleTier};

use crate::feed::store::{FeedStore, FeedStoreError};

/// Read host_iocs from the feed store and convert each into a FeedDeny
/// AllowlistEntry. Empty / null host_iocs are skipped at the SQL layer
/// (FeedStore::host_iocs filters `host_ioc IS NOT NULL`).
pub fn build_feeddeny_entries(
    feed_store: &FeedStore,
) -> Result<Vec<AllowlistEntry>, FeedStoreError> {
    let rows = feed_store.host_iocs()?;
    let mut out = Vec::with_capacity(rows.len());
    for row in rows {
        let host = match row.host_ioc.as_deref() {
            Some(h) if !h.is_empty() => h,
            _ => continue,
        };
        let (match_type, pattern) = classify_host(host);
        let reason = format!("feed:{}; advisory:{}", row.feed, row.advisory_id);
        out.push(AllowlistEntry {
            kind: RuleKind::Deny,
            tier: RuleTier::FeedDeny,
            match_type,
            pattern,
            reason,
        });
    }
    Ok(out)
}

/// Classify a host_ioc string into (MatchType, normalized pattern).
///
/// - `*.workers.dev` → (Suffix, `.workers.dev`) — leading `*` stripped per
///   suffix-pattern invariant (AllowlistEntry::matches treats Suffix patterns
///   as requiring a leading `.` to avoid `notworkers.dev` false-positives).
/// - `192.0.2.1` → (Ip, `192.0.2.1`)
/// - `evil.example.com` → (Exact, `evil.example.com`)
fn classify_host(host: &str) -> (MatchType, String) {
    if let Some(rest) = host.strip_prefix("*.") {
        return (MatchType::Suffix, format!(".{rest}"));
    }
    if host.parse::<std::net::IpAddr>().is_ok() {
        return (MatchType::Ip, host.to_string());
    }
    (MatchType::Exact, host.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::feed::store::FeedIocRow;

    fn host_row(advisory_id: &str, host: &str) -> FeedIocRow {
        FeedIocRow {
            feed: "OSV".to_string(),
            advisory_id: advisory_id.to_string(),
            ecosystem: String::new(),
            package: String::new(),
            versions_json: "{\"versions\":[],\"ranges\":[]}".to_string(),
            severity: None,
            tag: None,
            first_seen_ms: 0,
            host_ioc: Some(host.to_string()),
            schema_version_observed: "1.7.4".to_string(),
        }
    }

    #[test]
    fn classify_host_exact_for_plain_dns_name() {
        let (mt, p) = classify_host("evil.example.com");
        assert_eq!(mt, MatchType::Exact);
        assert_eq!(p, "evil.example.com");
    }

    #[test]
    fn classify_host_suffix_for_wildcard_with_leading_dot_normalized() {
        let (mt, p) = classify_host("*.workers.dev");
        assert_eq!(mt, MatchType::Suffix);
        assert_eq!(p, ".workers.dev", "leading-dot pattern for suffix match");
    }

    #[test]
    fn classify_host_ip_for_ipv4_literal() {
        let (mt, p) = classify_host("192.0.2.1");
        assert_eq!(mt, MatchType::Ip);
        assert_eq!(p, "192.0.2.1");
    }

    #[test]
    fn classify_host_ip_for_ipv6_literal() {
        let (mt, p) = classify_host("2001:db8::1");
        assert_eq!(mt, MatchType::Ip);
        assert_eq!(p, "2001:db8::1");
    }

    #[test]
    fn build_feeddeny_entries_emits_one_entry_per_host_ioc() {
        let store = FeedStore::open_in_memory().expect("in-memory store");
        store
            .upsert_iocs(&[
                host_row("MAL-2026-A", "evil.example.com"),
                host_row("MAL-2026-B", "192.0.2.1"),
                host_row("MAL-2026-C", "*.workers.dev"),
            ])
            .expect("upsert");

        let entries = build_feeddeny_entries(&store).expect("build");
        assert_eq!(entries.len(), 3);

        // All entries are Deny + FeedDeny tier.
        for e in &entries {
            assert_eq!(e.kind, RuleKind::Deny);
            assert_eq!(e.tier, RuleTier::FeedDeny);
            assert!(
                e.reason.starts_with("feed:OSV; advisory:MAL-2026-"),
                "reason should encode feed + advisory_id: {}",
                e.reason
            );
        }

        // Find each match_type by pattern.
        let exact = entries
            .iter()
            .find(|e| e.pattern == "evil.example.com")
            .expect("exact entry");
        assert_eq!(exact.match_type, MatchType::Exact);

        let ip = entries
            .iter()
            .find(|e| e.pattern == "192.0.2.1")
            .expect("ip entry");
        assert_eq!(ip.match_type, MatchType::Ip);

        let suffix = entries
            .iter()
            .find(|e| e.pattern == ".workers.dev")
            .expect("suffix entry (leading-dot normalized)");
        assert_eq!(suffix.match_type, MatchType::Suffix);
    }

    #[test]
    fn build_feeddeny_entries_empty_store_returns_empty_vec() {
        let store = FeedStore::open_in_memory().expect("in-memory store");
        let entries = build_feeddeny_entries(&store).expect("build");
        assert!(entries.is_empty());
    }

    #[test]
    fn build_feeddeny_entries_skips_rows_with_null_host_ioc() {
        // upsert one host-IoC row + one package-only row (host_ioc = None). The
        // package-only row is filtered out by FeedStore::host_iocs at the SQL
        // layer; this test verifies the integration end-to-end.
        let store = FeedStore::open_in_memory().expect("in-memory store");
        let mut pkg_row = host_row("MAL-2026-PKG", "ignored");
        pkg_row.host_ioc = None;
        pkg_row.ecosystem = "npm".to_string();
        pkg_row.package = "evil-pkg".to_string();
        store
            .upsert_iocs(&[host_row("MAL-2026-HOST", "evil.example.com"), pkg_row])
            .expect("upsert");

        let entries = build_feeddeny_entries(&store).expect("build");
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].pattern, "evil.example.com");
    }
}
