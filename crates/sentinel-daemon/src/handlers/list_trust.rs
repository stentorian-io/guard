//! crates/sentinel-daemon/src/handlers/list_trust.rs
//!
//! Phase 07 plan 01 — ListTrust handler (CLI-17 sentinel status trust).
//!
//! Read-only enumeration of rows in `trusted_policy_files`.

use sentinel_ipc::{ListTrust, ListTrustReply, TrustRow};

use crate::rule_store::RuleStore;

pub fn handle_list_trust(_req: &ListTrust, store: &RuleStore) -> ListTrustReply {
    match store.all_trusted_files() {
        Ok(rows) => ListTrustReply::ok(
            rows.into_iter()
                .map(|r| TrustRow {
                    canonical_path: r.canonical_path,
                    sha256: r.sha256,
                    trusted_at_ms: r.trusted_at_ms,
                    trusted_via: r.trusted_via,
                })
                .collect(),
        ),
        Err(e) => ListTrustReply::err(format!("rule_store: {e}")),
    }
}
