//! Daemon-side authorization for mutable management IPC.
//!
//! The system daemon socket may be world-writable in system mode, so peer
//! authentication and codesign checks are only the transport boundary. Mutating
//! management requests must also carry a user-approved, OS- or hardware-mediated
//! signature over the exact action the daemon is about to perform.

use guard_core::{
    ManagementActionPayloadV1, RuleSignaturePolicy, RuleSignatureV1,
    verify_management_action_signature,
};

use crate::rule_store::RuleStore;

pub const ACTION_DISABLE_CURATED_RULE: &str = "disable-curated-rule";
pub const ACTION_ENABLE_CURATED_RULE: &str = "enable-curated-rule";

/// Authorize a signed mutable management action.
///
/// # Errors
///
/// Returns a string error when the signature is missing, invalid, stale by
/// policy, or signed by an untrusted key.
pub fn authorize_management_action(
    rule_store: &RuleStore,
    policy: RuleSignaturePolicy,
    action: &str,
    pattern: &str,
    reason: &str,
    created_at_unix_ms: i64,
    signature: Option<&RuleSignatureV1>,
) -> Result<(), String> {
    if created_at_unix_ms <= 0 {
        return Err("signed management authorization required".into());
    }
    let Some(signature) = signature else {
        return Err("signed management authorization required".into());
    };

    let payload = ManagementActionPayloadV1::new(action, pattern, reason, created_at_unix_ms);
    verify_management_action_signature(&payload, signature, policy)
        .map_err(|e| format!("management authorization verification failed: {e}"))?;

    match rule_store.is_trusted_rule_signer(&signature.public_key_sha256, &signature.signer_kind) {
        Ok(true) => Ok(()),
        Ok(false) => Err(format!(
            "untrusted management signer: {}",
            signature.public_key_sha256
        )),
        Err(e) => Err(format!("rule_store: {e}")),
    }
}
