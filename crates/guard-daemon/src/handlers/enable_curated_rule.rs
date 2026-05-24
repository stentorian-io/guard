//! crates/guard-daemon/src/handlers/enable_curated_rule.rs
//!
//! v1.0 — EnableCuratedRule handler (stt-guard rules enable).
//!
//! Removes the override row from curated_overrides, re-enabling the
//! curated rule for future snapshots.

use guard_ipc::{EnableCuratedRule, EnableCuratedRuleReply};

use crate::management_auth::{ACTION_ENABLE_CURATED_RULE, authorize_management_action};
use crate::rule_store::RuleStore;

pub fn handle_enable_curated_rule(
    req: &EnableCuratedRule,
    rule_store: &RuleStore,
    policy: guard_core::RuleSignaturePolicy,
) -> EnableCuratedRuleReply {
    if req.pattern.trim().is_empty() {
        return EnableCuratedRuleReply::err("pattern must be non-empty");
    }
    if let Err(e) = authorize_management_action(
        rule_store,
        policy,
        ACTION_ENABLE_CURATED_RULE,
        &req.pattern,
        "",
        req.created_at_unix_ms,
        req.signature.as_ref(),
    ) {
        return EnableCuratedRuleReply::err(e);
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
        let p = guard_core::paths::db_path(tmp.path());
        let s = crate::rule_store::RuleStore::open(&p).expect("open");
        (tmp, s)
    }

    #[cfg(feature = "test-signer")]
    fn signed_req(pattern: &str) -> EnableCuratedRule {
        let created_at_unix_ms = 1_700_000_000_000;
        let payload = guard_core::ManagementActionPayloadV1::new(
            ACTION_ENABLE_CURATED_RULE,
            pattern,
            "",
            created_at_unix_ms,
        );
        let signature =
            guard_core::rule_signature::test_support::sign_management_action_with_test_simulator(
                &payload,
            )
            .expect("sign");
        EnableCuratedRule::new_signed(pattern, created_at_unix_ms, signature)
    }

    #[cfg(feature = "test-signer")]
    #[test]
    fn enable_disabled_pattern_returns_was_disabled_true() {
        let (_tmp, store) = open_store();
        store
            .disable_curated_rule("registry.npmjs.org", "test")
            .expect("disable");
        let req = signed_req("registry.npmjs.org");
        store
            .register_trusted_rule_signer(req.signature.as_ref().unwrap(), "test signer")
            .expect("trust signer");
        let reply = handle_enable_curated_rule(
            &req,
            &store,
            guard_core::RuleSignaturePolicy::AllowTestSimulator,
        );
        match reply {
            EnableCuratedRuleReply::Ok { was_disabled, .. } => {
                assert!(was_disabled, "should report was_disabled=true");
            }
            _ => panic!("expected Ok reply"),
        }
    }

    #[cfg(feature = "test-signer")]
    #[test]
    fn enable_not_disabled_pattern_returns_was_disabled_false() {
        let (_tmp, store) = open_store();
        let req = signed_req("registry.npmjs.org");
        store
            .register_trusted_rule_signer(req.signature.as_ref().unwrap(), "test signer")
            .expect("trust signer");
        let reply = handle_enable_curated_rule(
            &req,
            &store,
            guard_core::RuleSignaturePolicy::AllowTestSimulator,
        );
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
        let reply =
            handle_enable_curated_rule(&req, &store, guard_core::RuleSignaturePolicy::Production);
        assert!(matches!(reply, EnableCuratedRuleReply::Err { .. }));
    }

    #[test]
    fn unsigned_enable_existing_pattern_is_rejected() {
        let (_tmp, store) = open_store();
        let req = EnableCuratedRule::new("registry.npmjs.org");
        let reply =
            handle_enable_curated_rule(&req, &store, guard_core::RuleSignaturePolicy::Production);
        assert!(matches!(reply, EnableCuratedRuleReply::Err { .. }));
    }
}
