//! crates/guard-daemon/src/handlers/enable_curated_rule.rs
//!
//! v1.0 — EnableCuratedRule handler (stt-guard rules enable).
//!
//! Removes the override row from curated_overrides, re-enabling the
//! curated rule for future snapshots.

use guard_ipc::{EnableCuratedRule, EnableCuratedRuleReply};

use crate::rule_store::RuleStore;

pub fn handle_enable_curated_rule(
    req: &EnableCuratedRule,
    rule_store: &RuleStore,
) -> EnableCuratedRuleReply {
    if req.pattern.trim().is_empty() {
        return EnableCuratedRuleReply::err("pattern must be non-empty");
    }
    match rule_store.enable_curated_rule(&req.pattern) {
        Ok(was_disabled) => EnableCuratedRuleReply::ok(was_disabled),
        Err(e) => EnableCuratedRuleReply::err(format!("rule_store: {e}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use guard_ipc::EnableCuratedRuleReply;
    use tempfile::TempDir;

    fn open_store() -> (TempDir, crate::rule_store::RuleStore) {
        let tmp = TempDir::new().unwrap();
        let p = tmp.path().join("stt-guard.db");
        let s = crate::rule_store::RuleStore::open(&p).expect("open");
        (tmp, s)
    }

    #[test]
    fn enable_disabled_pattern_returns_was_disabled_true() {
        let (_tmp, store) = open_store();
        store
            .disable_curated_rule("registry.npmjs.org", "test")
            .expect("disable");
        let req = EnableCuratedRule::new("registry.npmjs.org");
        let reply = handle_enable_curated_rule(&req, &store);
        match reply {
            EnableCuratedRuleReply::Ok { was_disabled, .. } => {
                assert!(was_disabled, "should report was_disabled=true");
            }
            _ => panic!("expected Ok reply"),
        }
    }

    #[test]
    fn enable_not_disabled_pattern_returns_was_disabled_false() {
        let (_tmp, store) = open_store();
        let req = EnableCuratedRule::new("registry.npmjs.org");
        let reply = handle_enable_curated_rule(&req, &store);
        match reply {
            EnableCuratedRuleReply::Ok { was_disabled, .. } => {
                assert!(!was_disabled, "should report was_disabled=false");
            }
            _ => panic!("expected Ok reply"),
        }
    }

    #[test]
    fn enable_empty_pattern_returns_error() {
        let (_tmp, store) = open_store();
        let req = EnableCuratedRule::new("  ");
        let reply = handle_enable_curated_rule(&req, &store);
        assert!(matches!(reply, EnableCuratedRuleReply::Err { .. }));
    }
}
