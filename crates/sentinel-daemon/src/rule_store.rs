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
//! blocks `sentinel wrap` startup, which blocks the user's `npm install`.
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
use std::path::Path;
use std::sync::Mutex;

#[derive(Debug, thiserror::Error)]
pub enum RuleStoreError {
    #[error("sqlite: {0}")]
    Sql(#[from] rusqlite::Error),
    #[error("migrations: {0}")]
    Migrate(String),
}

/// Phase 07 plan 01 — storage-side row for ListRules. String discriminators
/// match the wire shape exactly so the handler does no enum mapping.
#[derive(Debug, Clone)]
pub struct StoredRule {
    pub source: String,     // "user" | "trusted_toml" | "builtin"
    pub kind: String,       // "allow" | "deny"
    pub match_type: String, // "exact" | "suffix" | "ip"
    pub pattern: String,
    pub reason: String,
    pub source_path: Option<String>,
}

/// Phase 07 plan 01 — storage-side row for ListTrust.
#[derive(Debug, Clone)]
pub struct StoredTrustEntry {
    pub canonical_path: String,
    pub sha256: String,
    pub trusted_at_ms: u64,
    pub trusted_via: String,
}

const SQL_001_INITIAL: &str = include_str!("../migrations/001_initial.sql");
const SQL_002_INSTALL_ARTIFACTS: &str = include_str!("../migrations/002_install_artifacts.sql");
const SQL_003_FEED_IOCS_AND_WAL: &str = include_str!("../migrations/003_feed_iocs_and_wal.sql");

pub struct RuleStore {
    /// Long-lived connection used for migrations + the write path
    /// (`insert_trusted`). Serializes all writes.
    conn: Mutex<Connection>,
    /// WR-05 fix: shared long-lived read-only connection. Replaces the
    /// per-query `open_reader()` pattern that opened a fresh Connection on
    /// every read call — unbounded under concurrent CLI invocations.
    /// WAL mode (enabled at open time) allows this reader and the writer
    /// to proceed concurrently without blocking each other.
    reader: Mutex<Connection>,
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

        let migrations = Migrations::new(vec![
            M::up(SQL_001_INITIAL),
            M::up(SQL_002_INSTALL_ARTIFACTS),
            M::up(SQL_003_FEED_IOCS_AND_WAL),
        ]);
        migrations
            .to_latest(&mut conn)
            .map_err(|e| RuleStoreError::Migrate(e.to_string()))?;

        // Phase 4 (D-89, plan 04-02): WAL applied at runtime per
        // 04-SPIKE-RESULTS.md A3 outcome. A PRAGMA-only M::up step silently
        // leaves journal_mode = delete (rusqlite_migration wraps each step in a
        // transaction; WAL change is rolled back). The runtime pragma_update
        // path works as expected.
        conn.pragma_update(None, "journal_mode", "WAL")
            .map_err(|e| RuleStoreError::Migrate(format!("WAL pragma: {e}")))?;
        let mode: String = conn
            .query_row("PRAGMA journal_mode", [], |r| r.get(0))
            .map_err(|e| RuleStoreError::Migrate(format!("verify WAL: {e}")))?;
        debug_assert_eq!(
            mode.to_lowercase(),
            "wal",
            "WAL mode must be active after migration (got {mode})"
        );

        // WR-05 fix: open a long-lived read-only connection so read-path
        // methods don't open/close a fresh connection per call.
        let reader = Connection::open_with_flags(
            db_path,
            OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )
        .map_err(RuleStoreError::Sql)?;

        Ok(Self {
            conn: Mutex::new(conn),
            reader: Mutex::new(reader),
        })
    }

    pub fn is_trusted(&self, path: &str, sha256: &str) -> SqlResult<bool> {
        let conn = self.reader.lock().expect("rule store reader mutex");
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

    /// Insert a user-approved rule (called by `sentinel approve` IPC handler in plan 03-11).
    /// Validates kind/match_type at the boundary; reason must be non-empty (D-39).
    /// Returns the new row id.
    pub fn insert_user_rule(&self, kind: &str, match_type: &str, pattern: &str, reason: &str) -> SqlResult<i64> {
        debug_assert!(matches!(kind, "allow" | "deny"));
        debug_assert!(matches!(match_type, "exact" | "suffix" | "ip"));
        debug_assert!(!reason.trim().is_empty(), "D-39: reason must be non-empty");
        let conn = self.conn.lock().expect("rule store mutex");
        let now = unix_ms_now();
        conn.execute(
            "INSERT INTO rules (kind, match_type, pattern, reason, created_at) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![kind, match_type, pattern, reason, now],
        )?;
        Ok(conn.last_insert_rowid())
    }

    /// Count all rows in the rules table (user-approved rules added via `sentinel approve`).
    /// Used by StatusReply handler in plan 03-08.
    pub fn count_user_rules(&self) -> SqlResult<u64> {
        let conn = self.reader.lock().expect("rule store reader mutex");
        conn.query_row("SELECT COUNT(*) FROM rules", [], |r| r.get::<_, i64>(0))
            .map(|n| n as u64)
    }

    /// Count all rows in the trusted_policy_files table.
    /// Used by StatusReply handler in plan 03-08.
    pub fn count_trusted(&self) -> SqlResult<u64> {
        let conn = self.reader.lock().expect("rule store reader mutex");
        conn.query_row("SELECT COUNT(*) FROM trusted_policy_files", [], |r| r.get::<_, i64>(0))
            .map(|n| n as u64)
    }

    /// Read all user rules; map each row to an AllowlistEntry with tier
    /// UserDeny / UserAllow. Used by plan 02-06's PrepareSnapshot handler.
    pub fn all_user_rules(&self) -> SqlResult<Vec<AllowlistEntry>> {
        let conn = self.reader.lock().expect("rule store reader mutex");
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

    /// Phase 07 plan 01 — enumerate user + trusted-toml rules for ListRules.
    ///
    /// Built-in / curated rules are NOT a parameter here: they live on
    /// `DaemonState.curated: Arc<Vec<AllowlistEntry>>` (loaded from
    /// `crates/sentinel-core/data/allowlist.yaml` via
    /// `crates/sentinel-daemon/src/curated.rs::load_curated()`). The
    /// caller (`handle_list_rules`) merges them in.
    pub fn all_rules_with_source(&self) -> SqlResult<Vec<StoredRule>> {
        let conn = self.reader.lock().expect("rule store reader mutex");
        let mut out: Vec<StoredRule> = Vec::new();

        let mut stmt = conn.prepare(
            "SELECT kind, match_type, pattern, reason FROM rules ORDER BY id",
        )?;
        let rows = stmt.query_map([], |row| {
            Ok(StoredRule {
                source: "user".into(),
                kind: row.get::<_, String>(0)?,
                match_type: row.get::<_, String>(1)?,
                pattern: row.get::<_, String>(2)?,
                reason: row.get::<_, String>(3)?,
                source_path: None,
            })
        })?;
        for r in rows {
            out.push(r?);
        }

        Ok(out)
    }

    /// Phase 07 plan 01 — enumerate trusted_policy_files rows for ListTrust.
    ///
    /// `trusted_at` is stored as unix-millis (verified: `insert_trusted` uses
    /// `unix_ms_now()` which returns ms since epoch). Map directly to
    /// `trusted_at_ms` without conversion.
    pub fn all_trusted_files(&self) -> SqlResult<Vec<StoredTrustEntry>> {
        let conn = self.reader.lock().expect("rule store reader mutex");
        let mut stmt = conn.prepare(
            "SELECT path, sha256, trusted_at, trusted_via FROM trusted_policy_files ORDER BY trusted_at",
        )?;
        let rows = stmt.query_map([], |row| {
            // trusted_at is unix-millis (i64 storage; widen to u64).
            let trusted_at_ms: i64 = row.get::<_, i64>(2)?;
            Ok(StoredTrustEntry {
                canonical_path: row.get::<_, String>(0)?,
                sha256: row.get::<_, String>(1)?,
                trusted_at_ms: trusted_at_ms.max(0) as u64,
                trusted_via: row.get::<_, String>(3)?,
            })
        })?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r?);
        }
        Ok(out)
    }
}

pub fn unix_ms_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64
}
