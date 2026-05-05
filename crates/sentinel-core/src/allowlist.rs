//! Hostname matcher — exact + suffix (D-16). No regex, no middle-wildcards.
//! Implemented in Task 2 of plan 01-03.

use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum AllowlistEntry {
    /// Exact hostname. e.g. "localhost", "registry.npmjs.org".
    Exact(String),
    /// Suffix match. Pattern MUST start with '.'. e.g. ".example.com".
    Suffix(String),
    /// Literal IP address (treated like Exact; just a different category for clarity).
    Ip(String),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verdict {
    Allow,
    Deny,
}

/// Decide allow/deny for `host` (the bytes of the hostname or numeric IP).
/// Returns Allow on first match; Deny if no entry matches.
pub fn match_hostname(entries: &[AllowlistEntry], host: &[u8]) -> Verdict {
    for entry in entries {
        match entry {
            AllowlistEntry::Exact(s) | AllowlistEntry::Ip(s) => {
                if s.as_bytes() == host {
                    return Verdict::Allow;
                }
            }
            AllowlistEntry::Suffix(s) => {
                let pat = s.as_bytes();
                // Suffix patterns MUST start with '.'; if not, treat as no-match
                // for safety (do not silently widen to substring).
                if pat.first() != Some(&b'.') {
                    continue;
                }
                if host.ends_with(pat) {
                    return Verdict::Allow;
                }
            }
        }
    }
    Verdict::Deny
}
