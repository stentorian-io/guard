//! crates/guard-daemon/src/prompt/suggested_rules.rs
//!
//! v0.3 — host-pattern -> SuggestedRule generator.

use guard_ipc::SuggestedRule;

/// Well-known shared-CDN second-level domains where a "exact match this SLD"
/// rule is a sensible suggestion. Excludes deny-list patterns (workers.dev,
/// pages.dev, etc. — see v0.2 ALLOW-06).
const SHARED_CDN_SLDS: &[&str] = &[
    "s3.amazonaws.com",
    "cloudfront.net",
    "blob.core.windows.net",
    "herokuapp.com",
    "vercel.app",
    "netlify.app",
    "github.io",
    "azurewebsites.net",
];

pub fn generate_suggested_rules(host: &str) -> Vec<SuggestedRule> {
    let mut out = Vec::new();
    // Always: exact-host.
    out.push(SuggestedRule {
        match_type: "exact".into(),
        pattern: host.to_string(),
    });

    // Raw IP: short-circuit (no suffix variants).
    if is_likely_ip(host) {
        return out;
    }

    let labels: Vec<&str> = host.split('.').collect();
    if labels.len() < 3 {
        return out;
    }

    // Detect shared-CDN: drop the leftmost label and check.
    let parent: String = labels[1..].join(".");
    if SHARED_CDN_SLDS.iter().any(|sld| parent == *sld) {
        out.push(SuggestedRule {
            match_type: "exact".into(),
            pattern: parent.clone(),
        });
    }

    // Fallback: suffix-rule on the parent (with leading dot).
    out.push(SuggestedRule {
        match_type: "suffix".into(),
        pattern: format!(".{parent}"),
    });

    out
}

fn is_likely_ip(host: &str) -> bool {
    host.parse::<std::net::Ipv4Addr>().is_ok() || host.parse::<std::net::Ipv6Addr>().is_ok()
}
