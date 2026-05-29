//! crates/guard-daemon/src/install_artifacts.rs
//!
//! v0.3 — `install_artifacts` CRUD.
//!
//! Records what the system installer did so uninstall can precisely reverse it.
//! Migrations are owned by `RuleStore`; this struct just opens connections to the same database.

use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use guard_ipc::InstallArtifact;
use rusqlite::{Connection, OpenFlags, Result as SqlResult, params};

pub struct InstallArtifactStore {
    conn: Mutex<Connection>,
    db_path: PathBuf,
}

impl InstallArtifactStore {
    /// Open against an already-migrated stt-guard.db (`RuleStore` owns the migration run).
    ///
    /// # Errors
    ///
    /// Returns an error when the database cannot be opened.
    pub fn open(db_path: &Path) -> SqlResult<Self> {
        let conn = Connection::open(db_path)?;
        Ok(Self {
            conn: Mutex::new(conn),
            db_path: db_path.to_path_buf(),
        })
    }

    /// Open an ephemeral in-memory store (for use in `DaemonState::new` stub / tests).
    /// The `install_artifacts` table is created inline since there is no migration runner
    /// for the in-memory case.
    ///
    /// # Errors
    ///
    /// Returns an error when the in-memory database cannot be opened or the table cannot be created.
    pub fn open_in_memory() -> SqlResult<Self> {
        let conn = Connection::open_in_memory()?;
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS install_artifacts (
                artifact_kind    TEXT NOT NULL,
                target_path      TEXT NOT NULL,
                content_hash     TEXT,
                installed_at     INTEGER NOT NULL,
                guard_version TEXT NOT NULL,
                PRIMARY KEY (artifact_kind, target_path)
            );",
        )?;
        Ok(Self {
            conn: Mutex::new(conn),
            db_path: std::path::PathBuf::from(":memory:"),
        })
    }

    pub fn db_path(&self) -> &Path {
        &self.db_path
    }

    /// List all recorded install artifacts.
    ///
    /// # Errors
    ///
    /// Returns an error when the query cannot be prepared or executed.
    pub fn list_all(&self) -> SqlResult<Vec<InstallArtifact>> {
        let conn = self
            .conn
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut stmt = conn.prepare(
            "SELECT artifact_kind, target_path, content_hash, installed_at, guard_version \
             FROM install_artifacts ORDER BY installed_at ASC",
        )?;
        let rows = stmt.query_map([], |row| {
            let installed_at: i64 = row.get(3)?;

            Ok(InstallArtifact {
                artifact_kind: row.get(0)?,
                target_path: row.get(1)?,
                content_hash: row.get(2)?,
                installed_at_ms: installed_at_ms_from_sql(installed_at)?,
                guard_version: row.get(4)?,
            })
        })?;
        rows.collect()
    }

    /// Insert or replace one install artifact row.
    ///
    /// # Errors
    ///
    /// Returns an error when the row cannot be written.
    pub fn insert(
        &self,
        artifact_kind: &str,
        target_path: &str,
        content_hash: Option<&str>,
        guard_version: &str,
    ) -> SqlResult<()> {
        let conn = self
            .conn
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let now = unix_ms_now();
        conn.execute(
            "INSERT OR REPLACE INTO install_artifacts \
             (artifact_kind, target_path, content_hash, installed_at, guard_version) \
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![artifact_kind, target_path, content_hash, now, guard_version],
        )?;
        Ok(())
    }

    /// Delete one install artifact row.
    ///
    /// # Errors
    ///
    /// Returns an error when the delete cannot be executed.
    pub fn delete(&self, artifact_kind: &str, target_path: &str) -> SqlResult<usize> {
        let conn = self
            .conn
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        conn.execute(
            "DELETE FROM install_artifacts WHERE artifact_kind = ?1 AND target_path = ?2",
            params![artifact_kind, target_path],
        )
    }

    /// v0.7 (WARNING-5 fix): bulk delete by `artifact_kind`. Used by
    /// the `DeleteInstallArtifacts` IPC handler so per-target `setup --remove`
    /// leaves no rows behind.
    ///
    /// # Errors
    ///
    /// Returns an error when the delete cannot be executed.
    pub fn delete_by_kind(&self, artifact_kind: &str) -> SqlResult<usize> {
        let conn = self
            .conn
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        conn.execute(
            "DELETE FROM install_artifacts WHERE artifact_kind = ?1",
            params![artifact_kind],
        )
    }

    /// Delete every install artifact row.
    ///
    /// # Errors
    ///
    /// Returns an error when the delete cannot be executed.
    pub fn delete_all(&self) -> SqlResult<usize> {
        let conn = self
            .conn
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        conn.execute("DELETE FROM install_artifacts", [])
    }
}

/// Daemon-down fallback: direct read-only open of the stt-guard.db.
/// Used by `stt-guard uninstall` CLI when daemon is unreachable.
///
/// # Errors
///
/// Returns an error when the database cannot be opened or read.
pub fn read_via_db(db_path: &Path) -> SqlResult<Vec<InstallArtifact>> {
    let conn = Connection::open_with_flags(
        db_path,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )?;
    let mut stmt = conn.prepare(
        "SELECT artifact_kind, target_path, content_hash, installed_at, guard_version \
         FROM install_artifacts ORDER BY installed_at ASC",
    )?;
    let rows = stmt.query_map([], |row| {
        let installed_at: i64 = row.get(3)?;

        Ok(InstallArtifact {
            artifact_kind: row.get(0)?,
            target_path: row.get(1)?,
            content_hash: row.get(2)?,
            installed_at_ms: installed_at_ms_from_sql(installed_at)?,
            guard_version: row.get(4)?,
        })
    })?;
    rows.collect()
}

fn unix_ms_now() -> i64 {
    let unix_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_millis());

    i64::try_from(unix_ms).unwrap_or(i64::MAX)
}

fn installed_at_ms_from_sql(installed_at: i64) -> SqlResult<u64> {
    u64::try_from(installed_at)
        .map_err(|_| rusqlite::Error::IntegralValueOutOfRange(3, installed_at))
}
