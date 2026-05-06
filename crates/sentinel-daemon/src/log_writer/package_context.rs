//! crates/sentinel-daemon/src/log_writer/package_context.rs
//!
//! Phase 3 plan 03-05 — package-context inference (D-54).
//!
//! Walks the existing ProcessTree from a given audit_token along parent links
//! until finding a ProcessNode with a non-None `pm_env_snapshot` (populated by
//! Phase 2's ExecEvent + Phase 3's pm_env extension — plan 03-04). Maps the
//! captured env subset to PackageContext per D-56.

use sentinel_core::AuditToken;
use sentinel_ipc::PackageContext;

use crate::tracked::ProcessTree;

/// Walk parent chain from `audit_token`. Returns Some when the closest ancestor
/// (or the node itself) has a pm_env_snapshot that produces a non-empty
/// PackageContext. Returns None on no PM signal — D-56 says "omit the field".
pub fn infer_package_context(
    process_tree: &ProcessTree,
    audit_token: &AuditToken,
    root_command: &str,
) -> Option<PackageContext> {
    let mut visited = 0usize;
    let mut current = process_tree.get_node(audit_token)?;
    loop {
        if let Some(env) = current.pm_env_snapshot.as_ref() {
            if let Some(ctx) = package_context_from_pm_env(env, root_command) {
                return Some(ctx);
            }
        }
        match current.parent_audit_token {
            Some(parent) => {
                visited += 1;
                if visited > 64 { return None; }   // defensive: walk depth cap
                current = process_tree.get_node(&parent)?;
            }
            None => return None,
        }
    }
}

/// Map a captured PM env subset → PackageContext. Returns None if no PM signal
/// strong enough to determine ecosystem.
pub fn package_context_from_pm_env(
    env: &[(String, String)],
    root_command: &str,
) -> Option<PackageContext> {
    let get = |key: &str| -> Option<String> {
        env.iter().find(|(k, _)| k == key).map(|(_, v)| v.clone())
    };
    // Order matters: npm_* before BUNDLE_* etc., since some envs leak across.
    let (ecosystem, package, version, lifecycle) = if env.iter().any(|(k, _)| k.starts_with("npm_")) {
        (
            "npm",
            get("npm_package_name")?,
            get("npm_package_version").unwrap_or_default(),
            get("npm_lifecycle_event"),
        )
    } else if env.iter().any(|(k, _)| k.starts_with("CARGO_")) {
        (
            "cargo",
            get("CARGO_PKG_NAME")?,
            get("CARGO_PKG_VERSION").unwrap_or_default(),
            None,
        )
    } else if env.iter().any(|(k, _)| k == "BUNDLE_GEMFILE" || k.starts_with("BUNDLE_")) {
        (
            "bundle",
            get("BUNDLE_GEMFILE").unwrap_or_else(|| "Gemfile".into()),
            String::new(),
            None,
        )
    } else if env.iter().any(|(k, _)| k.starts_with("PIP_") || k == "VIRTUAL_ENV") {
        (
            "pip",
            get("VIRTUAL_ENV").unwrap_or_else(|| "(unknown)".into()),
            String::new(),
            None,
        )
    } else if env.iter().any(|(k, _)| k.starts_with("GO") || k == "GOPATH" || k == "GOPROXY") {
        ("go", "(go)".into(), String::new(), None)
    } else if env.iter().any(|(k, _)| k.starts_with("MIX_")) {
        ("mix", "(mix)".into(), String::new(), get("MIX_ENV"))
    } else if env.iter().any(|(k, _)| k.starts_with("HEX_")) {
        ("hex", "(hex)".into(), String::new(), None)
    } else if env.iter().any(|(k, _)| k.starts_with("COMPOSER_")) {
        ("composer", "(composer)".into(), String::new(), None)
    } else {
        return None;
    };
    Some(PackageContext {
        ecosystem: ecosystem.to_string(),
        package,
        version,
        lifecycle,
        root_command: truncate_root_command(root_command),
    })
}

fn truncate_root_command(s: &str) -> String {
    const MAX: usize = 256;
    if s.len() <= MAX { return s.to_string(); }
    let mut end = MAX;
    while end > 0 && !s.is_char_boundary(end) { end -= 1; }
    s[..end].to_string()
}
