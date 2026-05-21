//! crates/guard-daemon/src/handlers/disable_curated_rule.rs
//!
//! v1.0 — DisableCuratedRule handler (stt-guard rules disable).
//!
//! Validates that the pattern is non-empty and matches at least one
//! curated rule before persisting the override to SQLite.

use guard_core::AllowlistEntry;
use guard_ipc::{DisableCuratedRule, DisableCuratedRuleReply};

use crate::rule_store::RuleStore;

pub fn handle_disable_curated_rule(
    req: &DisableCuratedRule,
    rule_store: &RuleStore,
    curated: &[AllowlistEntry],
) -> DisableCuratedRuleReply {
    if req.pattern.trim().is_empty() {
        return DisableCuratedRuleReply::err("pattern must be non-empty");
    }
    if req.reason.trim().is_empty() {
        return DisableCuratedRuleReply::err("reason must be non-empty");
    }
    // Verify the pattern matches an actual curated rule.
    let exists = curated.iter().any(|e| e.pattern == req.pattern);
    if !exists {
        return DisableCuratedRuleReply::err(format!(
            "no curated rule matches pattern {:?}",
            req.pattern
        ));
    }
    match rule_store.disable_curated_rule(&req.pattern, &req.reason) {
        Ok(()) => DisableCuratedRuleReply::ok(),
        Err(e) => DisableCuratedRuleReply::err(format!("rule_store: {e}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use guard_core::{AllowlistEntry, MatchType, RuleKind, RuleTier};
    use guard_ipc::DisableCuratedRuleReply;
    use tempfile::TempDir;

    fn fixture_curated() -> Vec<AllowlistEntry> {
        vec![
            AllowlistEntry {
                kind: RuleKind::Allow,
                tier: RuleTier::CuratedAllow,
                match_type: MatchType::Exact,
                pattern: "registry.npmjs.org".into(),
                reason: "npm registry".into(),
            },
            AllowlistEntry {
                kind: RuleKind::Allow,
                tier: RuleTier::CuratedAllow,
                match_type: MatchType::Exact,
                pattern: "pypi.org".into(),
                reason: "PyPI".into(),
            },
        ]
    }

    fn open_store() -> (TempDir, crate::rule_store::RuleStore) {
        let tmp = TempDir::new().unwrap();
        let p = tmp.path().join("stt-guard.db");
        let s = crate::rule_store::RuleStore::open(&p).expect("open");
        (tmp, s)
    }

    #[test]
    fn disable_existing_pattern_succeeds() {
        let (_tmp, store) = open_store();
        let req = DisableCuratedRule::new("registry.npmjs.org", "suspected compromise");
        let reply = handle_disable_curated_rule(&req, &store, &fixture_curated());
        assert!(matches!(reply, DisableCuratedRuleReply::Ok { .. }));
    }

    #[test]
    fn disable_nonexistent_pattern_returns_error() {
        let (_tmp, store) = open_store();
        let req = DisableCuratedRule::new("nonexistent.example.com", "reason");
        let reply = handle_disable_curated_rule(&req, &store, &fixture_curated());
        match reply {
            DisableCuratedRuleReply::Err { message, .. } => {
                assert!(
                    message.contains("no curated rule"),
                    "expected 'no curated rule' in message; got: {message}"
                );
            }
            _ => panic!("expected Err reply"),
        }
    }

    #[test]
    fn disable_empty_pattern_returns_error() {
        let (_tmp, store) = open_store();
        let req = DisableCuratedRule::new("", "reason");
        let reply = handle_disable_curated_rule(&req, &store, &fixture_curated());
        assert!(matches!(reply, DisableCuratedRuleReply::Err { .. }));
    }

    #[test]
    fn disable_empty_reason_returns_error() {
        let (_tmp, store) = open_store();
        let req = DisableCuratedRule::new("registry.npmjs.org", "  ");
        let reply = handle_disable_curated_rule(&req, &store, &fixture_curated());
        assert!(matches!(reply, DisableCuratedRuleReply::Err { .. }));
    }
}
