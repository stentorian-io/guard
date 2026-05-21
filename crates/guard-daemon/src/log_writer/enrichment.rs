//! Feed-based enrichment. Extracts advisory metadata from matching
//! AllowlistEntry reason fields (build-time-embedded IOCs carry the
//! advisory ID in the reason string, e.g. "MAL-2025-3008 supply-chain IOC (FEED)").

use guard_core::{AllowlistEntry, RuleTier};
use guard_ipc::{IntelMatch, PackageContext};

pub fn enrich(_pkg: &PackageContext) -> Vec<IntelMatch> {
    Vec::new()
}

pub fn enrich_for_host(_host: &str) -> Vec<IntelMatch> {
    Vec::new()
}

pub fn enrich_from_entries(host: &[u8], entries: &[AllowlistEntry]) -> Vec<IntelMatch> {
    let mut out = Vec::new();
    for entry in entries {
        if !matches!(entry.tier, RuleTier::ConfirmedDeny | RuleTier::SuspectDeny) {
            continue;
        }
        if !entry.matches(host) {
            continue;
        }
        let advisory_id = extract_advisory_id(&entry.reason);
        let confidence = match entry.tier {
            RuleTier::ConfirmedDeny => "confirmed",
            RuleTier::SuspectDeny => "suspect",
            _ => "unknown",
        };
        out.push(IntelMatch {
            feed: "OSV".to_string(),
            advisory_id,
            source: format!("host:{confidence}"),
            severity: None,
            tag: Some(confidence.to_string()),
            first_seen_ms: 0,
        });
    }
    out
}

fn extract_advisory_id(reason: &str) -> String {
    reason
        .split_whitespace()
        .next()
        .unwrap_or("unknown")
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use guard_core::{AllowlistEntry, MatchType, RuleKind, RuleTier};

    fn feed_entry(pattern: &str, tier: RuleTier, reason: &str) -> AllowlistEntry {
        AllowlistEntry {
            kind: RuleKind::Deny,
            tier,
            match_type: MatchType::Exact,
            pattern: pattern.into(),
            reason: reason.into(),
        }
    }

    #[test]
    fn enrich_from_entries_extracts_confirmed() {
        let entries = vec![feed_entry(
            "evil.com",
            RuleTier::ConfirmedDeny,
            "MAL-2025-001 supply-chain IOC (FEED)",
        )];
        let intel = enrich_from_entries(b"evil.com", &entries);
        assert_eq!(intel.len(), 1);
        assert_eq!(intel[0].advisory_id, "MAL-2025-001");
        assert_eq!(intel[0].tag.as_deref(), Some("confirmed"));
        assert_eq!(intel[0].source, "host:confirmed");
    }

    #[test]
    fn enrich_from_entries_extracts_suspect() {
        let entries = vec![feed_entry(
            "sketchy.io",
            RuleTier::SuspectDeny,
            "MAL-2025-002 supply-chain IOC (FEED)",
        )];
        let intel = enrich_from_entries(b"sketchy.io", &entries);
        assert_eq!(intel.len(), 1);
        assert_eq!(intel[0].tag.as_deref(), Some("suspect"));
    }

    #[test]
    fn enrich_skips_non_feed_tiers() {
        let entries = vec![
            feed_entry("evil.com", RuleTier::BuiltinDeny, "abuse pattern"),
            feed_entry("evil.com", RuleTier::ConfirmedDeny, "MAL-001 IOC"),
        ];
        let intel = enrich_from_entries(b"evil.com", &entries);
        assert_eq!(intel.len(), 1);
        assert_eq!(intel[0].advisory_id, "MAL-001");
    }

    #[test]
    fn enrich_skips_non_matching_host() {
        let entries = vec![feed_entry(
            "other.com",
            RuleTier::ConfirmedDeny,
            "MAL-001 IOC",
        )];
        let intel = enrich_from_entries(b"evil.com", &entries);
        assert!(intel.is_empty());
    }

    #[test]
    fn extract_advisory_id_parses_reason() {
        assert_eq!(
            extract_advisory_id("MAL-2025-3008 supply-chain IOC (FEED)"),
            "MAL-2025-3008"
        );
        assert_eq!(extract_advisory_id(""), "unknown");
    }
}
