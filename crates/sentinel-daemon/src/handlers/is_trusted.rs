//! crates/sentinel-daemon/src/handlers/is_trusted.rs
//!
//! Phase 07 plan 01 — IsTrusted handler (CLI-21 first-trust pre-check, D-24).
//!
//! Read-only existence check used by run_orchestrator::run BEFORE the
//! prompt fires. CLI canonicalizes the path before sending; this handler
//! rejects non-canonical wire input as defense-in-depth (Pitfall 4 —
//! prevents canonicalization mismatch from re-firing the prompt every run).
//!
//! T-07-01-01 mitigation: mirrors `handlers/trust_policy.rs` BLOCKER-03 fix
//! (lines 38-56) — `Path::canonicalize` then string-compare. The defense is
//! particularly important here because the (path, sha256) lookup key is
//! sensitive to path-normalization variance (`/x/.sentinel.toml` vs
//! `/x/./.sentinel.toml` would otherwise miss).

use std::path::Path;

use sentinel_ipc::{IsTrusted, IsTrustedReply};
use tracing::warn;

use crate::rule_store::RuleStore;

pub fn handle_is_trusted(req: &IsTrusted, store: &RuleStore) -> IsTrustedReply {
    let p = Path::new(&req.path);
    let canonical = match p.canonicalize() {
        Ok(c) => c,
        Err(e) => return IsTrustedReply::err(format!("canonicalize {}: {e}", req.path)),
    };
    let canonical_str = canonical.display().to_string();
    if canonical_str != req.path {
        warn!(
            wire_path = %req.path,
            canonical = %canonical_str,
            "IsTrusted path is not canonical — rejecting"
        );
        return IsTrustedReply::err(format!(
            "path not canonical (got {}, canonical {})",
            req.path, canonical_str
        ));
    }
    match store.is_trusted(&req.path, &req.sha256) {
        Ok(trusted) => IsTrustedReply::ok(trusted),
        Err(e) => IsTrustedReply::err(format!("rule_store: {e}")),
    }
}
