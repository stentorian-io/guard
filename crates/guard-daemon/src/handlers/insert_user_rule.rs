//! crates/guard-daemon/src/handlers/insert_user_rule.rs
//!
//! v0.3 — InsertUserRule handler (stt-guard approve).
//!
//! Validates kind/match_type/non-empty-reason/non-empty-pattern before calling
//! RuleStore::insert_user_rule. Returns InsertUserRuleReply::Ok { rule_id } on
//! success or InsertUserRuleReply::Err { message } on validation/storage failure.
//!
//! Tampering mitigation: validation happens HERE before any SQL call.
//! RuleStore::insert_user_rule uses parameterized queries; debug_asserts
//! provide defense-in-depth at the store boundary.

use guard_core::{verify_rule_signature, RuleSignaturePayloadV1, RuleSignaturePolicy};
use guard_ipc::{InsertUserRule, InsertUserRuleReply};

use crate::rule_store::RuleStore;

pub fn handle_insert_user_rule(
    req: &InsertUserRule,
    rule_store: &RuleStore,
    policy: RuleSignaturePolicy,
) -> InsertUserRuleReply {
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
    if req.created_at_unix_ms <= 0 {
        return InsertUserRuleReply::err("created_at_unix_ms must be present for signed rules");
    }
    if req.origin.trim().is_empty() {
        return InsertUserRuleReply::err("origin must be present for signed rules");
    }
    let Some(signature) = req.signature.as_ref() else {
        return InsertUserRuleReply::err("signed rule attestation required");
    };
    let payload = RuleSignaturePayloadV1::new(
        req.kind.clone(),
        req.match_type.clone(),
        req.pattern.clone(),
        req.reason.clone(),
        req.created_at_unix_ms,
        req.origin.clone(),
        req.run_uuid.clone(),
    );
    if let Err(e) = verify_rule_signature(&payload, signature, policy) {
        return InsertUserRuleReply::err(format!("rule signature verification failed: {e}"));
    }
    match rule_store.is_trusted_rule_signer(&signature.public_key_sha256, &signature.signer_kind) {
        Ok(true) => {}
        Ok(false) => {
            return InsertUserRuleReply::err(format!(
                "untrusted rule signer: {}",
                signature.public_key_sha256
            ));
        }
        Err(e) => return InsertUserRuleReply::err(format!("rule_store: {e}")),
    }
    match rule_store.insert_signed_user_rule(&payload, signature) {
        Ok(id) => InsertUserRuleReply::ok(id),
        Err(e) => InsertUserRuleReply::err(format!("rule_store: {e}")),
    }
}
