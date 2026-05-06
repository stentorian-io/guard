//! crates/sentinel-core/src/policy_file_writer.rs
//!
//! Round-trippable append to `.sentinel.toml` via `toml_edit` (D-48 / D-59).
//!
//! Preserves comments, key order, and blank lines on append. Re-serialization
//! via `toml` crate's to_string is FORBIDDEN — see RESEARCH.md Anti-Patterns.
//! Only `DocumentMut::to_string()` (from toml_edit) is permitted.

use toml_edit::{DocumentMut, Item, Table, value};

#[derive(Debug, thiserror::Error)]
pub enum WriteError {
    #[error("toml parse error: {0}")]
    ParseError(String),
    #[error("rules is not an ArrayOfTables")]
    InvalidRulesShape,
}

pub fn append_rule(
    existing_content: &str,
    kind: &str,        // "allow" | "deny"
    match_type: &str,  // "exact" | "suffix" | "ip"
    pattern: &str,
    reason: &str,
) -> Result<String, WriteError> {
    let mut doc = existing_content
        .parse::<DocumentMut>()
        .map_err(|e| WriteError::ParseError(e.to_string()))?;
    let rules = doc
        .entry("rules")
        .or_insert(Item::ArrayOfTables(Default::default()))
        .as_array_of_tables_mut()
        .ok_or(WriteError::InvalidRulesShape)?;
    let mut row = Table::new();
    row.insert("kind", value(kind));
    row.insert("match", value(match_type)); // wire key "match" — matches PolicyRule serde rename in policy_file.rs
    row.insert("pattern", value(pattern));
    row.insert("reason", value(reason));
    rules.push(row);
    Ok(doc.to_string())
}

/// Bulk variant for baseline-commit (D-59) — appends multiple rules in one parse/serialize cycle.
pub fn append_rules(
    existing_content: &str,
    rules_to_add: &[(&str, &str, &str, &str)], // (kind, match_type, pattern, reason)
) -> Result<String, WriteError> {
    let mut doc = existing_content
        .parse::<DocumentMut>()
        .map_err(|e| WriteError::ParseError(e.to_string()))?;
    let rules = doc
        .entry("rules")
        .or_insert(Item::ArrayOfTables(Default::default()))
        .as_array_of_tables_mut()
        .ok_or(WriteError::InvalidRulesShape)?;
    for (kind, match_type, pattern, reason) in rules_to_add {
        let mut row = Table::new();
        row.insert("kind", value(*kind));
        row.insert("match", value(*match_type));
        row.insert("pattern", value(*pattern));
        row.insert("reason", value(*reason));
        rules.push(row);
    }
    Ok(doc.to_string())
}
