//! Tier-ordered policy evaluator (RESEARCH.md §5).
//!
//! Hot-path discipline (D-03): no heap allocation. The evaluator iterates a
//! pre-sorted `&[AllowlistEntry]` and does only byte-comparison + the three
//! hard-rule checks. Returns a `(Verdict, SourceKind)` tuple by value; both
//! types are `Copy`, so no heap touch.

use crate::allowlist::{AllowlistEntry, RuleKind, RuleTier, Verdict};

/// Source attribution. Stored by the daemon's block-log for v0.3 surfacing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SourceKind {
    /// Hard rule encoded in this file. The &'static str names the rule —
    /// "loopback" | "cloud-metadata" | "raw-ip-cache-miss".
    HardRule(&'static str),
    BuiltinDeny,
    CuratedAllow,
    ConfirmedDeny,
    UserDeny,
    UserAllow,
    SuspectDeny,
    DefaultDeny,
}

impl SourceKind {
    fn from_tier(tier: RuleTier) -> Self {
        match tier {
            RuleTier::BuiltinDeny => SourceKind::BuiltinDeny,
            RuleTier::CuratedAllow => SourceKind::CuratedAllow,
            RuleTier::ConfirmedDeny => SourceKind::ConfirmedDeny,
            RuleTier::UserDeny => SourceKind::UserDeny,
            RuleTier::UserAllow => SourceKind::UserAllow,
            RuleTier::SuspectDeny => SourceKind::SuspectDeny,
        }
    }

    #[must_use]
    pub fn as_label(&self) -> &'static str {
        match self {
            SourceKind::HardRule("loopback") => "loopback",
            SourceKind::HardRule("cloud-metadata") => "cloud-metadata-blocked",
            SourceKind::HardRule("raw-ip-cache-miss") => "raw-ip-no-dns",
            SourceKind::HardRule("fail-closed") => "fail-closed",
            SourceKind::HardRule(_) => "hard-rule",
            SourceKind::BuiltinDeny => "builtin-deny",
            SourceKind::CuratedAllow => "curated-allow",
            SourceKind::ConfirmedDeny => "confirmed-deny",
            SourceKind::UserDeny => "user-deny",
            SourceKind::UserAllow => "user-allow",
            SourceKind::SuspectDeny => "suspect-deny",
            SourceKind::DefaultDeny => "default-deny",
        }
    }
}

// ============================================================================
// Hard rules (D-25) — encoded in code, non-overridable by any entry source.
// ============================================================================

/// Hostname-based loopback test. Matches `localhost` and `localhost6`.
#[must_use]
pub fn is_loopback_host(host: &[u8]) -> bool {
    host == b"localhost" || host == b"localhost6"
}

/// IP-string loopback test. Matches IPv4 127.0.0.0/8 (textually) and IPv6 `::1`.
#[must_use]
pub fn is_loopback_ip(ip: &[u8]) -> bool {
    if ip == b"::1" {
        return true;
    }
    // 127.x.y.z — accept any 127. prefix
    ip.starts_with(b"127.")
}

/// Cloud-metadata host test. AWS/Azure/GCP all use 169.254.169.254 (IPv4)
/// or `fe80::a9fe:a9fe` (IPv6 link-local) — D-25b.
///
/// WARNING-05 fix (v0.2 review): the previous implementation byte-compared
/// against `b"fe80::a9fe:a9fe"` only. The IPv6 link-local form has many
/// equivalent textual representations:
///   - `fe80::a9fe:a9fe`            (canonical lowercase, double-colon)
///   - `FE80::A9FE:A9FE`            (uppercase)
///   - `fe80:0:0:0:0:0:a9fe:a9fe`   (no double-colon compression)
///   - `fe80::a9fe:a9fe%en0`        (with link-scope ID)
///
/// `inet_ntop` on Darwin can return any of these depending on the address's
/// origin and flags. To make the hard rule fire regardless of textual form,
/// parse the input as an `Ipv6Addr` (rejecting any zone-id suffix first) and
/// compare the resulting 16-byte address to the IMDS magic constant.
#[must_use]
pub fn is_cloud_metadata_host(host: &[u8]) -> bool {
    // IPv4 fast path: byte-compare. The IPv4 textual form has a single
    // canonical representation per `inet_ntop` Darwin behaviour.
    if host == b"169.254.169.254" {
        return true;
    }
    // Reject empty / non-ASCII before parsing.
    if host.is_empty() {
        return false;
    }
    // IPv6 path: strip optional zone-id (`%foo`), parse as Ipv6Addr, compare
    // to the canonical link-local IMDS address fe80::a9fe:a9fe.
    let Ok(s) = core::str::from_utf8(host) else {
        return false;
    };
    let s = match s.split_once('%') {
        Some((addr, _zone)) => addr,
        None => s,
    };
    // Lowercase ASCII normalization for hex digits is implicit in
    // `Ipv6Addr::from_str` (case-insensitive). Avoid heap alloc — parse
    // directly. Most callers pass canonical lowercase already.
    if let Ok(addr) = s.parse::<core::net::Ipv6Addr>() {
        const IMDS_V6: core::net::Ipv6Addr =
            core::net::Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0xa9fe, 0xa9fe);
        return addr == IMDS_V6;
    }
    false
}

#[must_use]
pub fn is_cloud_metadata_ip(ip: &[u8]) -> bool {
    is_cloud_metadata_host(ip)
}

// ============================================================================
// Tier-ordered evaluator.
// ============================================================================

/// Evaluate a connection attempt against the snapshot's pre-sorted entries.
///
/// Inputs:
///   - `host`: bytes of the SNI / hostname (may be empty if connect-by-IP only)
///   - `ip`:   Some(ascii bytes) of the destination IP if known
///   - `resolved_via_getaddrinfo`: true if the dylib's per-process getaddrinfo
///     cache shows that the IP was resolved earlier in this process
///   - `entries`: pre-sorted by `RuleTier` (the daemon sorts at snapshot-write
///     time; the dylib mmaps already-sorted bytes)
///
/// The function iterates `entries` linearly and returns at the first match.
/// Because entries are sorted by tier, the first match is the highest-priority
/// match — implementing RESEARCH.md §5's five-tier precedence stack.
#[must_use]
pub fn evaluate_policy(
    host: &[u8],
    ip: Option<&[u8]>,
    resolved_via_getaddrinfo: bool,
    entries: &[AllowlistEntry],
) -> (Verdict, SourceKind) {
    // --- Tier 0a: loopback always-allow (D-25a) ---
    if !host.is_empty() && is_loopback_host(host) {
        return (Verdict::Allow, SourceKind::HardRule("loopback"));
    }
    if let Some(ip_bytes) = ip {
        if is_loopback_ip(ip_bytes) {
            return (Verdict::Allow, SourceKind::HardRule("loopback"));
        }
    }

    // --- Tier 0b: cloud metadata always-deny (D-25b) ---
    if !host.is_empty() && is_cloud_metadata_host(host) {
        return (Verdict::Deny, SourceKind::HardRule("cloud-metadata"));
    }
    if let Some(ip_bytes) = ip {
        if is_cloud_metadata_ip(ip_bytes) {
            return (Verdict::Deny, SourceKind::HardRule("cloud-metadata"));
        }
    }

    // --- Tier 0c: raw-IP cache-miss-deny (D-25c / ALLOW-08) ---
    // If we have an IP but no prior getaddrinfo for it, deny — the connect
    // happened with a hardcoded numeric address inside a tracked subtree.
    if ip.is_some() && !resolved_via_getaddrinfo {
        return (Verdict::Deny, SourceKind::HardRule("raw-ip-cache-miss"));
    }

    // --- Tiers 1..4: walk entries in tier order ---
    // Caller MUST supply pre-sorted entries (daemon's snapshot-write step does
    // this). On the dylib hot path we do not re-sort — that would allocate.
    for entry in entries {
        // Match against host first (most common case for hostname-based rules).
        // If host is empty or doesn't match, try matching against the IP string
        // for entries with match_type == Ip.
        if !host.is_empty() && entry.matches(host) {
            return verdict_for(entry);
        }
        if let Some(ip_bytes) = ip {
            if matches!(entry.match_type, crate::allowlist::MatchType::Ip)
                && entry.matches(ip_bytes)
            {
                return verdict_for(entry);
            }
        }
    }

    // --- Default deny ---
    (Verdict::Deny, SourceKind::DefaultDeny)
}

#[inline]
fn verdict_for(entry: &AllowlistEntry) -> (Verdict, SourceKind) {
    let v = match entry.kind {
        RuleKind::Allow => Verdict::Allow,
        RuleKind::Deny => Verdict::Deny,
    };
    (v, SourceKind::from_tier(entry.tier))
}

/// Check if a `UserAllow` entry exists for the given host. Used on the deny
/// path (not hot path) to detect "previously approved, now suspended" cases.
#[must_use]
pub fn has_user_allow(host: &[u8], entries: &[AllowlistEntry]) -> bool {
    entries
        .iter()
        .any(|e| matches!(e.tier, crate::allowlist::RuleTier::UserAllow) && e.matches(host))
}
