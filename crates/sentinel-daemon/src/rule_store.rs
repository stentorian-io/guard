//! SQLite rule store and trusted-policy-files table (POL-01 + D-37).
//!
//! Owned by the daemon. The dylib never reads SQLite directly — instead, the
//! daemon merges SQLite rules into the per-run snapshot at PrepareSnapshot
//! time (plan 02-06).
//!
//! WARNING-08 fix (Phase 2 review): the original implementation wrapped a
//! single `Connection` in a process-global `Mutex`, serializing ALL
//! rule-store reads (`is_trusted`, `all_user_rules`) and ALL writes
//! (`insert_trusted`) through one lock. Under heavy fork load the daemon's
//! 16 worker threads contended on this mutex, effectively reducing
//! rule-store concurrency to 1 — which blocks `PrepareSnapshot`, which
//! blocks `sentinel run` startup, which blocks the user's `npm install`.
//!
//! The fix opens a fresh `Connection` per read call. SQLite supports this
//! natively (file-level locking + WAL mode handles concurrent readers
//! cleanly). Writes still take a mutex on the long-lived connection so
//! migrations and the singleton `INSERT OR REPLACE` path are serialized.
//! In WAL mode this would also be true with separate connections, but the
//! current schema does not yet enable WAL — keeping the write path on a
//! shared mutex preserves the existing behaviour while removing the read
//! contention.

use rusqlite::{params, Connection, OpenFlags, Result as SqlResult};
use rusqlite_migration::{Migrations, M};
use sentinel_core::{AllowlistEntry, MatchType, RuleKind, RuleTier};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

#[derive(Debug, thiserror::Error)]
pub enum RuleStoreError {
    #[error("sqlite: {0}")]
    Sql(#[from] rusqlite::Error),
    #[error("migrations: {0}")]
    Migrate(String),
}

const SQL_001_INITIAL: &str = include_str!("../migrations/001_initial.sql");
const SQL_002_INSTALL_ARTIFACTS: &str = include_str!("../migrations/002_install_artifacts.sql");

pub struct RuleStore {
    /// Long-lived connection used for migrations + the write path
    /// (`insert_trusted`). Reads open a fresh connection per call so they
    /// do NOT contend on this mutex. See WARNING-08.
    conn: Mutex<Connection>,
    db_path: PathBuf,
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

        let migrations = Migrations::new(vec![M::up(SQL_001_INITIAL), M::up(SQL_002_INSTALL_ARTIFACTS)]);
        migrations
            .to_latest(&mut conn)
            .map_err(|e| RuleStoreError::Migrate(e.to_string()))?;

        Ok(Self {
            conn: Mutex::new(conn),
            db_path: db_path.to_path_buf(),
        })
    }

    /// Open a fresh read-only connection to the same DB file. Used by
    /// read-path methods so they don't contend on the writer's mutex
    /// (WARNING-08). On error, the caller surfaces the SQLite error to its
    /// own caller; the long-lived writer connection is unaffected.
    fn open_reader(&self) -> SqlResult<Connection> {
        Connection::open_with_flags(
            &self.db_path,
            OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )
    }

    pub fn is_trusted(&self, path: &str, sha256: &str) -> SqlResult<bool> {
        // WARNING-08: fresh per-call read connection — no contention with
        // concurrent writers or other readers.
        let conn = self.open_reader()?;
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
        // Writes still take the shared writer mutex so migrations and the
        // singleton `INSERT OR REPLACE` are serialized.
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
        // WARNING-08: fresh per-call read connection.
        let conn = self.open_reader()?;
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
