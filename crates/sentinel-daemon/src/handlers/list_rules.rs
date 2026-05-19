//! crates/sentinel-daemon/src/handlers/list_rules.rs
//!
//! v0.7 — ListRules handler (sentinel status rules).
//!
//! Reads user rules from the SQLite store and returns them as wire-friendly
//! RuleRow records. CLI is a dumb client.

use sentinel_core::{AllowlistEntry, MatchType, RuleKind};
use sentinel_ipc::{ListRules, ListRulesReply, RuleRow};

use crate::rule_store::{RuleStore, StoredRule};

/// v0.7 — handle ListRules.
///
/// Sources merged into the reply:
///   1. User rules — SQLite `rules` table via `RuleStore::all_rules_with_source`,
///      emitted with `source = "user"`.
///   2. Built-in / curated rules (when `req.include_builtins == true`, `--all`):
///      sourced from the in-memory `curated: Arc<Vec<AllowlistEntry>>` on
///      `DaemonState`. The slice is loaded once at daemon startup by
///      `crates/sentinel-daemon/src/curated.rs::load_curated()` from the
///      compile-time-embedded YAML at `crates/sentinel-core/data/allowlist.yaml`.
///      This is the authoritative source — `RuleStore` does NOT hold these rows.
///      Verified: `ipc_server.rs:190` (`pub curated: Arc<Vec<sentinel_core::AllowlistEntry>>`)
///      and `prepare_snapshot.rs:69` (the snapshot handler already merges this
///      slice with user rules via the same shape — we mirror its access path).
pub fn handle_list_rules(
    req: &ListRules,
    store: &RuleStore,
    curated: &[AllowlistEntry],
) -> ListRulesReply {
    let mut rows: Vec<RuleRow> = match store.all_rules_with_source() {
        Ok(rs) => rs.into_iter().map(rule_row_from_storage).collect(),
        Err(e) => return ListRulesReply::err(format!("rule_store: {e}")),
    };
    if req.include_builtins {
        for e in curated {
            rows.push(curated_to_rule_row(e));
        }
    }
    ListRulesReply::ok(rows)
}

/// Convert the SQL-row tuple into a wire RuleRow. Defines the string
/// discriminator vocabulary the CLI/tests depend on.
fn rule_row_from_storage(row: StoredRule) -> RuleRow {
    RuleRow {
        source: row.source,
        kind: row.kind,
        match_type: row.match_type,
        pattern: row.pattern,
        reason: row.reason,
    }
}

/// Map a curated AllowlistEntry to the wire shape with `source = "builtin"`.
/// Match-type strings mirror the InsertUserRule discriminator vocabulary
/// (per `RuleStore::insert_user_rule` validation: "exact" | "suffix" | "ip").
fn curated_to_rule_row(e: &AllowlistEntry) -> RuleRow {
    let kind = match e.kind {
        RuleKind::Allow => "allow",
        RuleKind::Deny => "deny",
    };
    let match_type = match e.match_type {
        MatchType::Exact => "exact",
        MatchType::Suffix => "suffix",
        MatchType::Ip => "ip",
    };
    RuleRow {
        source: "builtin".into(),
        kind: kind.into(),
        match_type: match_type.into(),
        pattern: e.pattern.clone(),
        reason: e.reason.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sentinel_core::{AllowlistEntry, MatchType, RuleKind, RuleTier};
    use sentinel_ipc::ListRulesReply;
    use tempfile::TempDir;

    fn fixture_curated() -> Vec<AllowlistEntry> {
        vec![AllowlistEntry {
            kind: RuleKind::Allow,
            tier: RuleTier::CuratedAllow,
            match_type: MatchType::Suffix,
            pattern: ".npmjs.org".into(),
            reason: "test fixture: registry".into(),
        }]
    }

    fn empty_store() -> (TempDir, RuleStore) {
        let tmp = TempDir::new().unwrap();
        let p = tmp.path().join("sentinel.db");
        let s = RuleStore::open(&p).expect("open");
        (tmp, s)
    }

    #[test]
    fn include_builtins_false_omits_curated() {
        let (_tmp, store) = empty_store();
        let req = ListRules::new(false);
        let reply = handle_list_rules(&req, &store, &fixture_curated());
        match reply {
            ListRulesReply::Ok { rules, .. } => {
                assert!(
                    rules.iter().all(|r| r.source != "builtin"),
                    "no builtin rows when include_builtins=false; got {rules:?}"
                );
            }
            ListRulesReply::Err { message, .. } => panic!("unexpected err: {message}"),
        }
    }

    #[test]
    fn include_builtins_true_emits_curated_rows() {
        let (_tmp, store) = empty_store();
        let req = ListRules::new(true);
        let reply = handle_list_rules(&req, &store, &fixture_curated());
        match reply {
            ListRulesReply::Ok { rules, .. } => {
                let builtins: Vec<&RuleRow> =
                    rules.iter().filter(|r| r.source == "builtin").collect();
                assert_eq!(builtins.len(), 1, "exactly one builtin row");
                let r = builtins[0];
                assert_eq!(r.kind, "allow");
                assert_eq!(r.match_type, "suffix");
                assert_eq!(r.pattern, ".npmjs.org");
            }
            ListRulesReply::Err { message, .. } => panic!("unexpected err: {message}"),
        }
    }
}
