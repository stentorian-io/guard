//! SQLite rule store and trusted-policy-files table (POL-01 + D-37).
//!
//! Owned by the daemon. The dylib never reads SQLite directly — instead, the
//! daemon merges SQLite rules into the per-run snapshot at PrepareSnapshot
//! time (plan 02-06).

use rusqlite::{params, Connection, Result as SqlResult};
use rusqlite_migration::{Migrations, M};
use sentinel_core::{AllowlistEntry, MatchType, RuleKind, RuleTier};
use std::path::Path;
use std::sync::Mutex;

#[derive(Debug, thiserror::Error)]
pub enum RuleStoreError {
    #[error("sqlite: {0}")]
    Sql(#[from] rusqlite::Error),
    #[error("migrations: {0}")]
    Migrate(String),
}

const SQL_001_INITIAL: &str = include_str!("../migrations/001_initial.sql");

pub struct RuleStore {
    conn: Mutex<Connection>,
}

impl RuleStore {
    /// Open or create the SQLite database at `db_path`. On creation, sets
    /// mode 0600. Idempotent — runs migrations to latest on every open.
    pub fn open(db_path: &Path) -> Result<Self, RuleStoreError> {
        let mut conn = Connection::open(db_path).map_err(RuleStoreError::Sql)?;
        // Defense-in-depth: tighten file permissions if the DB file was just
        // created. macOS umask varies; explicit chmod is the safe path.
        if let Ok(meta) = std::fs::metadata(db_path) {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = meta.permissions();
            perms.set_mode(0o600);
            let _ = std::fs::set_permissions(db_path, perms);
        }

        let migrations = Migrations::new(vec![M::up(SQL_001_INITIAL)]);
        migrations
            .to_latest(&mut conn)
            .map_err(|e| RuleStoreError::Migrate(e.to_string()))?;

        Ok(Self {
            conn: Mutex::new(conn),
        })
    }

    pub fn is_trusted(&self, path: &str, sha256: &str) -> SqlResult<bool> {
        let conn = self.conn.lock().expect("rule store mutex");
        let count: u32 = conn.query_row(
            "SELECT COUNT(*) FROM trusted_policy_files WHERE path = ?1 AND sha256 = ?2",
            params![path, sha256],
            |row| row.get(0),
        )?;
        Ok(count > 0)
    }

    pub fn insert_trusted(
        &self,
        path: &str,
        sha256: &str,
        trusted_via: &str,
    ) -> SqlResult<()> {
        debug_assert!(
            matches!(trusted_via, "cli" | "prompt"),
            "trusted_via must be 'cli' or 'prompt'; got {trusted_via}"
        );
        let conn = self.conn.lock().expect("rule store mutex");
        let now = unix_ms_now();
        conn.execute(
            "INSERT OR REPLACE INTO trusted_policy_files (path, sha256, trusted_at, trusted_via) VALUES (?1, ?2, ?3, ?4)",
            params![path, sha256, now, trusted_via],
        )?;
        Ok(())
    }

    /// Read all user rules; map each row to an AllowlistEntry with tier
    /// UserDeny / UserAllow. Used by plan 02-06's PrepareSnapshot handler.
    pub fn all_user_rules(&self) -> SqlResult<Vec<AllowlistEntry>> {
        let conn = self.conn.lock().expect("rule store mutex");
        let mut stmt = conn.prepare(
            "SELECT kind, match_type, pattern, reason FROM rules ORDER BY id",
        )?;
        let rows = stmt.query_map([], |row| {
            let kind_str: String = row.get(0)?;
            let match_str: String = row.get(1)?;
            let pattern: String = row.get(2)?;
            let reason: String = row.get(3)?;
            let kind = match kind_str.as_str() {
                "allow" => RuleKind::Allow,
                "deny" => RuleKind::Deny,
                other => {
                    return Err(rusqlite::Error::FromSqlConversionFailure(
                        0,
                        rusqlite::types::Type::Text,
                        format!("invalid kind: {other}").into(),
                    ));
                }
            };
            let match_type = match match_str.as_str() {
                "exact" => MatchType::Exact,
                "suffix" => MatchType::Suffix,
                "ip" => MatchType::Ip,
                other => {
                    return Err(rusqlite::Error::FromSqlConversionFailure(
                        0,
                        rusqlite::types::Type::Text,
                        format!("invalid match_type: {other}").into(),
                    ));
                }
            };
            let tier = match kind {
                RuleKind::Allow => RuleTier::UserAllow,
                RuleKind::Deny => RuleTier::UserDeny,
            };
            Ok(AllowlistEntry {
                kind,
                tier,
                match_type,
                pattern,
                reason,
            })
        })?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r?);
        }
        Ok(out)
    }
}

fn unix_ms_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64
}
