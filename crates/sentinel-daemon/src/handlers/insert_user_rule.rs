//! crates/sentinel-daemon/src/handlers/insert_user_rule.rs
//!
//! Phase 3 plan 03-08 — InsertUserRule handler (CLI-04 sentinel approve).
//!
//! Validates kind/match_type/non-empty-reason/non-empty-pattern before calling
//! RuleStore::insert_user_rule. Returns InsertUserRuleReply::Ok { rule_id } on
//! success or InsertUserRuleReply::Err { message } on validation/storage failure.
//!
//! T-03-08-01 (Tampering): validation happens HERE before any SQL call.
//! RuleStore::insert_user_rule uses parameterized queries; debug_asserts
//! provide defense-in-depth at the store boundary (plan 03-04).

use sentinel_ipc::{InsertUserRule, InsertUserRuleReply};

use crate::rule_store::RuleStore;

pub fn handle_insert_user_rule(req: &InsertUserRule, rule_store: &RuleStore) -> InsertUserRuleReply {
    if !matches!(req.kind.as_str(), "allow" | "deny") {
        return InsertUserRuleReply::err(format!("invalid kind: {}", req.kind));
    }
    if !matches!(req.match_type.as_str(), "exact" | "suffix" | "ip") {
        return InsertUserRuleReply::err(format!("invalid match_type: {}", req.match_type));
    }
    if req.reason.trim().is_empty() {
        return InsertUserRuleReply::err("reason must be non-empty (D-39)");
    }
    if req.pattern.trim().is_empty() {
        return InsertUserRuleReply::err("pattern must be non-empty");
    }
    match rule_store.insert_user_rule(&req.kind, &req.match_type, &req.pattern, &req.reason) {
        Ok(id) => InsertUserRuleReply::ok(id),
        Err(e) => InsertUserRuleReply::err(format!("rule_store: {e}")),
    }
}
