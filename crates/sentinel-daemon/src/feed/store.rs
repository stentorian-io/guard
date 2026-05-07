//! Phase 4 plan 04-02 — FeedStore CRUD against `feed_iocs` and `feed_metadata`
//! tables. Migrations are owned by `RuleStore` (the SQL_003_FEED_IOCS_AND_WAL
//! step is registered there); `FeedStore::open` opens against an
//! already-migrated `sentinel.db`, mirroring `install_artifacts.rs`.
//!
//! Concurrency discipline (per WARNING-08 / `rule_store.rs`):
//!   - Reads (`query_by_pkg`, `host_iocs`, `read_metadata`) use a fresh
//!     `Connection::open_with_flags(SQLITE_OPEN_READ_ONLY | SQLITE_OPEN_NO_MUTEX)`.
//!   - Writes (`upsert_iocs`, `delete_feed`, `update_metadata`) take
//!     `self.conn.lock()`.
//!
//! WAL is enabled by `RuleStore::open` so concurrent reader connections never
//! contend with the writer mutex.

use std::path::{Path, PathBuf};
use std::sync::Mutex;

use rusqlite::{params, Connection, OpenFlags, Result as SqlResult};

pub use crate::rule_store::unix_ms_now;

#[derive(Debug, thiserror::Error)]
pub enum FeedStoreError {
    #[error("sqlite: {0}")]
    Sql(#[from] rusqlite::Error),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FeedIocRow {
    pub feed: String,
    pub advisory_id: String,
    pub ecosystem: String,
    pub package: String,
    pub versions_json: String,
    pub severity: Option<String>,
    pub tag: Option<String>,
    pub first_seen_ms: i64,
    pub host_ioc: Option<String>,
    pub schema_version_observed: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FeedMetadataRow {
    pub feed: String,
    pub last_pull_ms: i64,
    pub last_pull_outcome: String,
    pub last_commit_sha: Option<String>,
    pub schema_version_observed: Option<String>,
    pub error_message: Option<String>,
    pub record_count: i64,
}

pub struct FeedStore {
    /// Long-lived writer connection. Reads open a fresh per-call read-only
    /// connection (see `open_reader`).
    conn: Mutex<Connection>,
    db_path: PathBuf,
}

impl FeedStore {
    /// Open against an already-migrated sentinel.db (RuleStore owns the
    /// migration run including SQL_003_FEED_IOCS_AND_WAL).
    pub fn open(db_path: &Path) -> Result<Self, FeedStoreError> {
        let conn = Connection::open(db_path)?;
        Ok(Self {
            conn: Mutex::new(conn),
            db_path: db_path.to_path_buf(),
        })
    }

    /// Open an ephemeral in-memory store (for use in DaemonState::new stub /
    /// tests). The feed_iocs + feed_metadata tables are created inline since
    /// there is no migration runner for the in-memory case.
    pub fn open_in_memory() -> Result<Self, FeedStoreError> {
        let conn = Connection::open_in_memory()?;
        conn.execute_batch(include_str!("../../migrations/003_feed_iocs_and_wal.sql"))?;
        Ok(Self {
            conn: Mutex::new(conn),
            db_path: PathBuf::from(":memory:"),
        })
    }

    pub fn db_path(&self) -> &Path {
        &self.db_path
    }

    /// True iff the store was constructed via `open_in_memory()` — the read
    /// helpers below detect this and serve reads from the writer connection
    /// rather than opening a fresh `:memory:` reader (which would be a brand-
    /// new empty SQLite database, not the same one carrying the schema).
    fn is_in_memory(&self) -> bool {
        self.db_path.as_os_str() == ":memory:"
    }

    fn open_reader(&self) -> SqlResult<Connection> {
        Connection::open_with_flags(
            &self.db_path,
            OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )
    }

    /// Insert-or-replace per the migration's PRIMARY KEY
    /// `(feed, advisory_id, ecosystem, package, host_ioc)`. Returns the number
    /// of rows attempted (i.e. `rows.len()`); SQLite returns 1 per upsert
    /// regardless of whether it was an insert or replace.
    pub fn upsert_iocs(&self, rows: &[FeedIocRow]) -> Result<usize, FeedStoreError> {
        if rows.is_empty() {
            return Ok(0);
        }
        let mut conn = self.conn.lock().unwrap_or_else(|p| p.into_inner());
        let tx = conn.transaction()?;
        {
            let mut stmt = tx.prepare(
                "INSERT OR REPLACE INTO feed_iocs \
                 (feed, advisory_id, ecosystem, package, versions_json, severity, tag, \
                  first_seen_ms, host_ioc, schema_version_observed) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
            )?;
            for r in rows {
                debug_assert!(
                    matches!(r.feed.as_str(), "OSV" | "GHSA"),
                    "feed must be 'OSV' or 'GHSA'; got {}",
                    r.feed
                );
                stmt.execute(params![
                    r.feed,
                    r.advisory_id,
                    r.ecosystem,
                    r.package,
                    r.versions_json,
                    r.severity,
                    r.tag,
                    r.first_seen_ms,
                    r.host_ioc,
                    r.schema_version_observed,
                ])?;
            }
        }
        tx.commit()?;
        Ok(rows.len())
    }

    /// Delete all rows for `feed`. Used by parse-on-fetch idempotency
    /// (D-88: each fetch fully replaces the prior parse).
    pub fn delete_feed(&self, feed: &str) -> Result<usize, FeedStoreError> {
        debug_assert!(
            matches!(feed, "OSV" | "GHSA"),
            "feed must be 'OSV' or 'GHSA'; got {feed}"
        );
        let conn = self.conn.lock().unwrap_or_else(|p| p.into_inner());
        let n = conn.execute("DELETE FROM feed_iocs WHERE feed = ?1", params![feed])?;
        Ok(n)
    }

    /// CR-01 fix: Atomically replace ALL rows for `feed` with `rows` in a
    /// single SQLite transaction. Without this, a concurrent reader on a
    /// separate WAL connection (e.g., another `sentinel run`'s
    /// `build_feeddeny_entries`, or a log-enrichment `host_iocs()` call) can
    /// observe an empty `feed_iocs` window between a `delete_feed` commit
    /// and the subsequent `upsert_iocs` commit — landing an empty FeedDeny
    /// set in a parallel snapshot and silently weakening core
    /// supply-chain enforcement during the refresh window.
    ///
    /// Returns the number of rows inserted (same shape as `upsert_iocs`).
    /// `feed_fetch_mutex` only serializes WRITERS; readers do not contend
    /// on it (by WARNING-08 design), so the atomicity guarantee here is
    /// reader-visibility, not writer-serialization.
    pub fn replace_feed_iocs(
        &self,
        feed: &str,
        rows: &[FeedIocRow],
    ) -> Result<usize, FeedStoreError> {
        debug_assert!(
            matches!(feed, "OSV" | "GHSA"),
            "feed must be 'OSV' or 'GHSA'; got {feed}"
        );
        let mut conn = self.conn.lock().unwrap_or_else(|p| p.into_inner());
        let tx = conn.transaction()?;
        tx.execute("DELETE FROM feed_iocs WHERE feed = ?1", params![feed])?;
        {
            let mut stmt = tx.prepare(
                "INSERT OR REPLACE INTO feed_iocs \
                 (feed, advisory_id, ecosystem, package, versions_json, severity, tag, \
                  first_seen_ms, host_ioc, schema_version_observed) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
            )?;
            for r in rows {
                debug_assert!(
                    matches!(r.feed.as_str(), "OSV" | "GHSA"),
                    "feed must be 'OSV' or 'GHSA'; got {}",
                    r.feed
                );
                debug_assert!(
                    r.feed.as_str() == feed,
                    "replace_feed_iocs: row feed mismatch: outer={feed}, row={}",
                    r.feed
                );
                stmt.execute(params![
                    r.feed,
                    r.advisory_id,
                    r.ecosystem,
                    r.package,
                    r.versions_json,
                    r.severity,
                    r.tag,
                    r.first_seen_ms,
                    r.host_ioc,
                    r.schema_version_observed,
                ])?;
            }
        }
        tx.commit()?;
        Ok(rows.len())
    }

    pub fn query_by_pkg(
        &self,
        ecosystem: &str,
        package: &str,
    ) -> Result<Vec<FeedIocRow>, FeedStoreError> {
        const SQL: &str =
            "SELECT feed, advisory_id, ecosystem, package, versions_json, severity, tag, \
             first_seen_ms, host_ioc, schema_version_observed \
             FROM feed_iocs WHERE ecosystem = ?1 AND package = ?2";
        if self.is_in_memory() {
            let conn = self.conn.lock().unwrap_or_else(|p| p.into_inner());
            let mut stmt = conn.prepare(SQL)?;
            let rows = stmt.query_map(params![ecosystem, package], row_to_ioc)?;
            let mut out = Vec::new();
            for r in rows {
                out.push(r?);
            }
            return Ok(out);
        }
        let conn = self.open_reader()?;
        let mut stmt = conn.prepare(SQL)?;
        let rows = stmt.query_map(params![ecosystem, package], row_to_ioc)?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r?);
        }
        Ok(out)
    }

    pub fn host_iocs(&self) -> Result<Vec<FeedIocRow>, FeedStoreError> {
        const SQL: &str =
            "SELECT feed, advisory_id, ecosystem, package, versions_json, severity, tag, \
             first_seen_ms, host_ioc, schema_version_observed \
             FROM feed_iocs WHERE host_ioc IS NOT NULL";
        if self.is_in_memory() {
            let conn = self.conn.lock().unwrap_or_else(|p| p.into_inner());
            let mut stmt = conn.prepare(SQL)?;
            let rows = stmt.query_map([], row_to_ioc)?;
            let mut out = Vec::new();
            for r in rows {
                out.push(r?);
            }
            return Ok(out);
        }
        let conn = self.open_reader()?;
        let mut stmt = conn.prepare(SQL)?;
        let rows = stmt.query_map([], row_to_ioc)?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r?);
        }
        Ok(out)
    }

    pub fn read_metadata(&self, feed: &str) -> Result<Option<FeedMetadataRow>, FeedStoreError> {
        debug_assert!(
            matches!(feed, "OSV" | "GHSA"),
            "feed must be 'OSV' or 'GHSA'; got {feed}"
        );
        const SQL: &str =
            "SELECT feed, last_pull_ms, last_pull_outcome, last_commit_sha, \
             schema_version_observed, error_message, record_count \
             FROM feed_metadata WHERE feed = ?1";
        let map = |row: &rusqlite::Row<'_>| -> SqlResult<FeedMetadataRow> {
            Ok(FeedMetadataRow {
                feed: row.get(0)?,
                last_pull_ms: row.get(1)?,
                last_pull_outcome: row.get(2)?,
                last_commit_sha: row.get(3)?,
                schema_version_observed: row.get(4)?,
                error_message: row.get(5)?,
                record_count: row.get(6)?,
            })
        };
        if self.is_in_memory() {
            let conn = self.conn.lock().unwrap_or_else(|p| p.into_inner());
            let mut stmt = conn.prepare(SQL)?;
            let mut rows = stmt.query_map(params![feed], map)?;
            return match rows.next() {
                Some(r) => Ok(Some(r?)),
                None => Ok(None),
            };
        }
        let conn = self.open_reader()?;
        let mut stmt = conn.prepare(SQL)?;
        let mut rows = stmt.query_map(params![feed], map)?;
        match rows.next() {
            Some(r) => Ok(Some(r?)),
            None => Ok(None),
        }
    }

    /// Read every row of `feed_metadata` (typically 0..2 rows: OSV + GHSA).
    /// Used by `compute_daemon_state` (plan 04-03) to inspect per-feed
    /// `last_pull_outcome` so the daemon can promote to `Degraded` on parse
    /// failures (TI-06 surfacing).
    pub fn read_all_metadata(&self) -> Result<Vec<FeedMetadataRow>, FeedStoreError> {
        const SQL: &str =
            "SELECT feed, last_pull_ms, last_pull_outcome, last_commit_sha, \
             schema_version_observed, error_message, record_count \
             FROM feed_metadata";
        let map = |row: &rusqlite::Row<'_>| -> SqlResult<FeedMetadataRow> {
            Ok(FeedMetadataRow {
                feed: row.get(0)?,
                last_pull_ms: row.get(1)?,
                last_pull_outcome: row.get(2)?,
                last_commit_sha: row.get(3)?,
                schema_version_observed: row.get(4)?,
                error_message: row.get(5)?,
                record_count: row.get(6)?,
            })
        };
        if self.is_in_memory() {
            let conn = self.conn.lock().unwrap_or_else(|p| p.into_inner());
            let mut stmt = conn.prepare(SQL)?;
            let rows = stmt.query_map([], map)?;
            let mut out = Vec::new();
            for r in rows {
                out.push(r?);
            }
            return Ok(out);
        }
        let conn = self.open_reader()?;
        let mut stmt = conn.prepare(SQL)?;
        let rows = stmt.query_map([], map)?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r?);
        }
        Ok(out)
    }

    pub fn update_metadata(&self, row: &FeedMetadataRow) -> Result<(), FeedStoreError> {
        debug_assert!(
            matches!(row.feed.as_str(), "OSV" | "GHSA"),
            "feed must be 'OSV' or 'GHSA'; got {}",
            row.feed
        );
        debug_assert!(
            matches!(
                row.last_pull_outcome.as_str(),
                "ok" | "network_error" | "parse_error" | "schema_unknown" | "panic"
            ),
            "last_pull_outcome must be one of the 5 CHECK values; got {}",
            row.last_pull_outcome
        );
        let conn = self.conn.lock().unwrap_or_else(|p| p.into_inner());
        conn.execute(
            "INSERT OR REPLACE INTO feed_metadata \
             (feed, last_pull_ms, last_pull_outcome, last_commit_sha, \
              schema_version_observed, error_message, record_count) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                row.feed,
                row.last_pull_ms,
                row.last_pull_outcome,
                row.last_commit_sha,
                row.schema_version_observed,
                row.error_message,
                row.record_count,
            ],
        )?;
        Ok(())
    }
}

fn row_to_ioc(row: &rusqlite::Row<'_>) -> SqlResult<FeedIocRow> {
    Ok(FeedIocRow {
        feed: row.get(0)?,
        advisory_id: row.get(1)?,
        ecosystem: row.get(2)?,
        package: row.get(3)?,
        versions_json: row.get(4)?,
        severity: row.get(5)?,
        tag: row.get(6)?,
        first_seen_ms: row.get(7)?,
        host_ioc: row.get(8)?,
        schema_version_observed: row.get(9)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rule_store::RuleStore;
    use std::sync::{Arc, Barrier};
    use tempfile::tempdir;

    fn open_with_migrations() -> (tempfile::TempDir, FeedStore) {
        let dir = tempdir().expect("tempdir");
        let db = dir.path().join("sentinel.db");
        // RuleStore::open registers SQL_003_FEED_IOCS_AND_WAL and applies WAL.
        let _store = RuleStore::open(&db).expect("rule store open + migrations");
        let feed_store = FeedStore::open(&db).expect("feed store open");
        (dir, feed_store)
    }

    #[test]
    fn migration_003_creates_feed_iocs_with_indexes() {
        let dir = tempdir().expect("tempdir");
        let db = dir.path().join("sentinel.db");
        let _store = RuleStore::open(&db).expect("rule store open");

        let conn = Connection::open(&db).expect("open verify");
        let mut stmt = conn
            .prepare("SELECT name FROM sqlite_master WHERE type='index' AND tbl_name='feed_iocs'")
            .expect("prepare");
        let names: Vec<String> = stmt
            .query_map([], |r| r.get::<_, String>(0))
            .expect("query")
            .map(|r| r.expect("row"))
            .collect();
        assert!(
            names.iter().any(|n| n == "idx_feed_iocs_pkg"),
            "expected idx_feed_iocs_pkg, got {:?}",
            names
        );
        assert!(
            names.iter().any(|n| n == "idx_feed_iocs_host"),
            "expected idx_feed_iocs_host, got {:?}",
            names
        );

        // feed_metadata table exists.
        let count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='feed_metadata'",
                [],
                |r| r.get(0),
            )
            .expect("query metadata table");
        assert_eq!(count, 1);
    }

    #[test]
    fn wal_mode_active_after_open() {
        let dir = tempdir().expect("tempdir");
        let db = dir.path().join("sentinel.db");
        let _store = RuleStore::open(&db).expect("rule store open");
        let conn = Connection::open(&db).expect("verify");
        let mode: String = conn
            .query_row("PRAGMA journal_mode", [], |r| r.get(0))
            .expect("query journal_mode");
        assert_eq!(mode.to_lowercase(), "wal", "WAL must be active");
    }

    fn sample_row(feed: &str, advisory_id: &str, host_ioc: Option<&str>) -> FeedIocRow {
        FeedIocRow {
            feed: feed.to_string(),
            advisory_id: advisory_id.to_string(),
            ecosystem: "npm".to_string(),
            package: "evil-pkg".to_string(),
            versions_json: r#"{"versions":["1.0.0"],"ranges":[]}"#.to_string(),
            severity: Some("HIGH".to_string()),
            tag: Some("malicious".to_string()),
            first_seen_ms: 1_700_000_000_000,
            host_ioc: host_ioc.map(String::from),
            schema_version_observed: "1.7.4".to_string(),
        }
    }

    #[test]
    fn feed_store_upsert_then_query_by_pkg_roundtrips() {
        let (_dir, store) = open_with_migrations();
        let rows = vec![
            sample_row("OSV", "MAL-2026-1", None),
            sample_row("OSV", "MAL-2026-2", None),
        ];
        let n = store.upsert_iocs(&rows).expect("upsert");
        assert_eq!(n, 2);

        let got = store.query_by_pkg("npm", "evil-pkg").expect("query");
        assert_eq!(got.len(), 2);
        let ids: Vec<&str> = got.iter().map(|r| r.advisory_id.as_str()).collect();
        assert!(ids.contains(&"MAL-2026-1"));
        assert!(ids.contains(&"MAL-2026-2"));
    }

    #[test]
    fn feed_store_host_iocs_filters_null() {
        let (_dir, store) = open_with_migrations();
        let rows = vec![
            sample_row("OSV", "MAL-2026-A", Some("evil.example.com")),
            sample_row("OSV", "MAL-2026-B", None),
        ];
        store.upsert_iocs(&rows).expect("upsert");

        let hosts = store.host_iocs().expect("host_iocs");
        assert_eq!(hosts.len(), 1);
        assert_eq!(hosts[0].host_ioc.as_deref(), Some("evil.example.com"));
    }

    #[test]
    fn feed_store_update_metadata_persists() {
        let (_dir, store) = open_with_migrations();
        let row = FeedMetadataRow {
            feed: "OSV".to_string(),
            last_pull_ms: 1_700_000_000_000,
            last_pull_outcome: "ok".to_string(),
            last_commit_sha: Some("abc1234".to_string()),
            schema_version_observed: Some("1.7.4".to_string()),
            error_message: None,
            record_count: 10,
        };
        store.update_metadata(&row).expect("update");
        let got = store.read_metadata("OSV").expect("read").expect("present");
        assert_eq!(got, row);

        // None for unknown feed (GHSA never written).
        let ghsa = store.read_metadata("GHSA").expect("read GHSA");
        assert!(ghsa.is_none());
    }

    #[test]
    fn feed_store_replace_feed_iocs_is_atomic_swap() {
        // CR-01 fix: pre-seed rows for a feed, then call replace_feed_iocs
        // with a different rowset. The DELETE + INSERTs must run in a single
        // transaction so the on-disk view either holds the old rows or the
        // new rows — never an empty intermediate set.
        let (_dir, store) = open_with_migrations();
        store
            .upsert_iocs(&[
                sample_row("OSV", "MAL-2026-OLD", None),
                sample_row("OSV", "MAL-2026-OLD-2", None),
            ])
            .expect("seed");

        let new_rows = vec![sample_row("OSV", "MAL-2026-NEW", None)];
        let n = store
            .replace_feed_iocs("OSV", &new_rows)
            .expect("replace");
        assert_eq!(n, 1);

        let after = store.query_by_pkg("npm", "evil-pkg").expect("query");
        let ids: Vec<&str> = after.iter().map(|r| r.advisory_id.as_str()).collect();
        assert!(ids.contains(&"MAL-2026-NEW"), "new row present: {ids:?}");
        assert!(!ids.contains(&"MAL-2026-OLD"), "old row purged: {ids:?}");
        assert!(
            !ids.contains(&"MAL-2026-OLD-2"),
            "second old row purged: {ids:?}"
        );
    }

    #[test]
    fn feed_store_replace_feed_iocs_per_feed_isolation() {
        // replace_feed_iocs("OSV", ...) must NOT touch GHSA rows.
        let (_dir, store) = open_with_migrations();
        store
            .upsert_iocs(&[
                sample_row("OSV", "MAL-2026-OSV-OLD", None),
                sample_row("GHSA", "GHSA-KEEP-1", None),
            ])
            .expect("seed");

        let new_osv = vec![sample_row("OSV", "MAL-2026-OSV-NEW", None)];
        store
            .replace_feed_iocs("OSV", &new_osv)
            .expect("replace OSV");

        let rows = store.query_by_pkg("npm", "evil-pkg").expect("query");
        let ids: Vec<&str> = rows.iter().map(|r| r.advisory_id.as_str()).collect();
        assert!(ids.contains(&"GHSA-KEEP-1"), "GHSA untouched: {ids:?}");
        assert!(ids.contains(&"MAL-2026-OSV-NEW"), "OSV swapped: {ids:?}");
        assert!(
            !ids.contains(&"MAL-2026-OSV-OLD"),
            "old OSV purged: {ids:?}"
        );
    }

    #[test]
    fn feed_store_delete_feed_idempotency() {
        let (_dir, store) = open_with_migrations();
        store
            .upsert_iocs(&[sample_row("OSV", "MAL-2026-X", None)])
            .expect("upsert");
        let n = store.delete_feed("OSV").expect("delete");
        assert_eq!(n, 1);
        let after = store.query_by_pkg("npm", "evil-pkg").expect("query");
        assert_eq!(after.len(), 0);
    }

    #[test]
    fn feed_store_query_by_pkg_uses_open_reader() {
        // Spawn 32 concurrent readers + 1 writer. Verify no deadlock and reads
        // see consistent data. WAL mode + open_reader pattern means each read
        // opens its own connection; writes serialize through self.conn mutex.
        let (dir, store) = open_with_migrations();
        let store = Arc::new(store);
        let dir = Arc::new(dir);
        let barrier = Arc::new(Barrier::new(33));

        // Pre-seed.
        store
            .upsert_iocs(&[sample_row("OSV", "MAL-2026-CONC", None)])
            .expect("seed");

        let mut handles = Vec::new();
        for _ in 0..32 {
            let s = Arc::clone(&store);
            let b = Arc::clone(&barrier);
            handles.push(std::thread::spawn(move || {
                b.wait();
                for _ in 0..16 {
                    let rows = s.query_by_pkg("npm", "evil-pkg").expect("read");
                    assert!(!rows.is_empty(), "reader saw empty");
                }
            }));
        }
        // Writer thread.
        {
            let s = Arc::clone(&store);
            let b = Arc::clone(&barrier);
            handles.push(std::thread::spawn(move || {
                b.wait();
                for i in 0..8 {
                    let r = sample_row("OSV", &format!("MAL-2026-W-{i}"), None);
                    s.upsert_iocs(&[r]).expect("write");
                }
            }));
        }
        for h in handles {
            h.join().expect("thread");
        }
        // Final verification.
        let got = store.query_by_pkg("npm", "evil-pkg").expect("read");
        assert!(got.len() >= 1, "expected at least seed row");
        // Hold dir until all threads finished.
        drop(dir);
    }
}
