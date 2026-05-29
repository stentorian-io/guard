//! `SQLite` rule store.
//!
//! Owned by the daemon. The dylib never reads `SQLite` directly — instead, the
//! daemon merges `SQLite` rules into the per-run snapshot at `PrepareSnapshot`
//! time.
//!
//! WARNING fix (v0.2 review): the original implementation wrapped a
//! single `Connection` in a process-global `Mutex`, serializing ALL
//! rule-store reads (`all_user_rules`) and ALL writes through one lock.
//! Under heavy fork load the daemon's 16 worker threads contended on this
//! mutex, effectively reducing rule-store concurrency to 1 — which blocks
//! `PrepareSnapshot`, which blocks `stt-guard wrap` startup, which blocks
//! the user's `npm install`.
//!
//! The fix opens a fresh `Connection` per read call. `SQLite` supports this
//! natively (file-level locking + WAL mode handles concurrent readers
//! cleanly). Writes still take a mutex on the long-lived connection so
//! migrations and the singleton write path are serialized. In WAL mode this
//! would also be true with separate connections, but keeping the write path
//! on a shared mutex preserves the existing behaviour while removing the
//! read contention.

use guard_core::{
    AllowlistEntry, MatchType, RuleKind, RuleSignaturePayloadV1, RuleSignaturePolicy,
    RuleSignatureV1, RuleTier, paths, verify_rule_signature,
};
use rusqlite::{Connection, OpenFlags, OptionalExtension, Result as SqlResult, params};
use rusqlite_migration::{M, Migrations};
use std::collections::HashSet;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

#[derive(Debug, thiserror::Error)]
pub enum RuleStoreError {
    #[error("sqlite: {0}")]
    Sql(#[from] rusqlite::Error),
    #[error("migrations: {0}")]
    Migrate(String),
    #[error("rule signature: {0}")]
    Signature(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuleSigningStatus {
    pub configured: bool,
    pub status: String,
    pub signer_kind: Option<String>,
    pub fingerprint: Option<String>,
    pub trust_root_path: Option<String>,
    pub trust_root_ok: bool,
    pub reason: Option<String>,
    pub action: Option<String>,
}

/// v0.7 — storage-side row for `ListRules`. String discriminators
/// match the wire shape exactly so the handler does no enum mapping.
#[derive(Debug, Clone)]
pub struct StoredRule {
    pub source: String,     // "user" | "builtin"
    pub kind: String,       // "allow" | "deny"
    pub match_type: String, // "exact" | "suffix" | "ip"
    pub pattern: String,
    pub reason: String,
}

struct TrustedManifestSigner {
    fingerprint: String,
    signer_kind: String,
    public_key_hex: String,
}

struct VerifiedRuleRow {
    kind: String,
    match_type: String,
    pattern: String,
    reason: String,
    created_at: i64,
    scheme: String,
    signer_kind: String,
    public_key_x963: Vec<u8>,
    public_key_sha256: String,
    signature_der: Vec<u8>,
    signed_payload_sha256: String,
    signature_created_at_unix_ms: i64,
    origin: String,
    run_uuid: Option<String>,
    payload_created_at: i64,
}

const SQL_001_SCHEMA: &str = include_str!("../migrations/001_schema.sql");
const SQL_002_CURATED_OVERRIDES: &str = include_str!("../migrations/002_curated_overrides.sql");
const SQL_003_RULE_SIGNATURES: &str = include_str!("../migrations/003_rule_signatures.sql");

pub struct RuleStore {
    /// Long-lived connection used for migrations + the write path.
    /// Serializes all writes.
    conn: Mutex<Connection>,
    /// WR-05 fix: shared long-lived read-only connection. Replaces the
    /// per-query `open_reader()` pattern that opened a fresh Connection on
    /// every read call — unbounded under concurrent CLI invocations.
    /// WAL mode (enabled at open time) allows this reader and the writer
    /// to proceed concurrently without blocking each other.
    reader: Mutex<Connection>,
    trusted_signers_manifest_path: Option<PathBuf>,
}

impl RuleStore {
    /// Open or create the `SQLite` database at `db_path`. On creation, sets
    /// mode 0600. Idempotent — runs migrations to latest on every open.
    ///
    /// # Errors
    ///
    /// Returns database, migration, or trusted-signer manifest errors.
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
            M::up(SQL_001_SCHEMA),
            M::up(SQL_002_CURATED_OVERRIDES),
            M::up(SQL_003_RULE_SIGNATURES),
        ]);
        migrations
            .to_latest(&mut conn)
            .map_err(|e| RuleStoreError::Migrate(e.to_string()))?;

        conn.pragma_update(None, "foreign_keys", "ON")
            .map_err(|e| RuleStoreError::Migrate(format!("foreign_keys pragma: {e}")))?;

        // WAL pragma must be applied outside the migration transaction —
        // rusqlite_migration wraps each M::up in a transaction, which causes
        // the journal_mode change to be silently rolled back.
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
        reader
            .pragma_update(None, "foreign_keys", "ON")
            .map_err(|e| RuleStoreError::Migrate(format!("reader foreign_keys pragma: {e}")))?;

        let trusted_signers_manifest_path =
            if db_path.parent() == Some(Path::new(paths::SYSTEM_STATE_DIR)) {
                Some(paths::trusted_rule_signers_path())
            } else {
                None
            };

        Ok(Self {
            conn: Mutex::new(conn),
            reader: Mutex::new(reader),
            trusted_signers_manifest_path,
        })
    }

    /// Insert a user-approved rule (called by legacy tests and pre-signature paths).
    /// New persistence paths must use `insert_signed_user_rule`.
    /// Validates `kind/match_type` at the boundary; reason must be non-empty.
    /// Returns the new row id.
    ///
    /// # Errors
    ///
    /// Returns `SQLite` errors from inserting the rule.
    ///
    /// # Panics
    ///
    /// Panics if the rule-store mutex is poisoned.
    pub fn insert_user_rule(
        &self,
        kind: &str,
        match_type: &str,
        pattern: &str,
        reason: &str,
    ) -> SqlResult<i64> {
        debug_assert!(matches!(kind, "allow" | "deny"));
        debug_assert!(matches!(match_type, "exact" | "suffix" | "ip"));
        debug_assert!(!reason.trim().is_empty(), "reason must be non-empty");
        let conn = self.conn.lock().expect("rule store mutex");
        let now = unix_ms_now();
        conn.execute(
            "INSERT INTO rules (kind, match_type, pattern, reason, created_at) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![kind, match_type, pattern, reason, now],
        )?;
        Ok(conn.last_insert_rowid())
    }

    /// Insert a signed user rule and its authenticity metadata in one transaction.
    ///
    /// # Errors
    ///
    /// Returns `SQLite` or rule-store errors from inserting the rule and
    /// signature metadata.
    ///
    /// # Panics
    ///
    /// Panics if the rule-store mutex is poisoned.
    pub fn insert_signed_user_rule(
        &self,
        payload: &RuleSignaturePayloadV1,
        signature: &RuleSignatureV1,
    ) -> Result<i64, RuleStoreError> {
        debug_assert!(matches!(payload.kind.as_str(), "allow" | "deny"));
        debug_assert!(matches!(
            payload.match_type.as_str(),
            "exact" | "suffix" | "ip"
        ));
        debug_assert!(
            !payload.reason.trim().is_empty(),
            "reason must be non-empty"
        );
        let mut conn = self.conn.lock().expect("rule store mutex");
        let tx = conn.transaction()?;
        tx.execute(
            "INSERT INTO rules (kind, match_type, pattern, reason, created_at) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                payload.kind,
                payload.match_type,
                payload.pattern,
                payload.reason,
                payload.created_at_unix_ms
            ],
        )?;
        let rule_id = tx.last_insert_rowid();
        tx.execute(
            "INSERT INTO rule_signatures (
                rule_id, scheme, signer_kind, public_key_x963, public_key_sha256,
                signature_der, signed_payload_sha256, signature_created_at,
                origin, run_uuid, payload_created_at
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
            params![
                rule_id,
                signature.scheme,
                signature.signer_kind,
                signature.public_key_x963,
                signature.public_key_sha256,
                signature.signature_der,
                signature.signed_payload_sha256,
                signature.signature_created_at_unix_ms,
                payload.origin,
                payload.run_uuid,
                payload.created_at_unix_ms,
            ],
        )?;
        tx.commit()?;
        Ok(rule_id)
    }

    /// Enroll a public rule-signing key as trusted. Production enrollment must
    /// happen only after hardware attestation; tests use this for the explicit
    /// test simulator signer.
    ///
    /// # Errors
    ///
    /// Returns `SQLite` errors from persisting the trusted signer.
    pub fn register_trusted_rule_signer(
        &self,
        signature: &RuleSignatureV1,
        label: &str,
    ) -> Result<(), RuleStoreError> {
        self.register_trusted_rule_signer_key(
            &signature.public_key_sha256,
            &signature.signer_kind,
            &signature.public_key_x963,
            label,
        )
    }

    /// Enroll a trusted rule-signing public key directly.
    ///
    /// # Errors
    ///
    /// Returns `SQLite` errors from persisting the trusted signer.
    ///
    /// # Panics
    ///
    /// Panics if the rule-store mutex is poisoned.
    pub fn register_trusted_rule_signer_key(
        &self,
        public_key_sha256: &str,
        signer_kind: &str,
        public_key_x963: &[u8],
        label: &str,
    ) -> Result<(), RuleStoreError> {
        let conn = self.conn.lock().expect("rule store mutex");
        conn.execute(
            "INSERT OR REPLACE INTO trusted_rule_signers (
                public_key_sha256, signer_kind, public_key_x963, enrolled_at, label
             ) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                public_key_sha256,
                signer_kind,
                public_key_x963,
                unix_ms_now(),
                label,
            ],
        )?;
        Ok(())
    }

    /// Check whether a rule signer is trusted in both the database and manifest.
    ///
    /// # Errors
    ///
    /// Returns `SQLite` or trusted-signer manifest verification errors.
    ///
    /// # Panics
    ///
    /// Panics if the rule-store reader mutex is poisoned.
    pub fn is_trusted_rule_signer(
        &self,
        public_key_sha256: &str,
        signer_kind: &str,
    ) -> Result<bool, RuleStoreError> {
        let conn = self.reader.lock().expect("rule store reader mutex");
        let count: i64 = conn.query_row(
            "SELECT COUNT(*) FROM trusted_rule_signers
             WHERE public_key_sha256 = ?1 AND signer_kind = ?2",
            params![public_key_sha256, signer_kind],
            |r| r.get(0),
        )?;
        if count != 1 {
            return Ok(false);
        }
        self.trusted_manifest_contains(public_key_sha256, signer_kind, None)
    }

    pub fn rule_signing_status(&self) -> RuleSigningStatus {
        let Some(path) = &self.trusted_signers_manifest_path else {
            return Self::rule_signing_status_no_trust_root();
        };
        let trust_root_path = Some(path.display().to_string());

        if let Err(e) = Self::verify_trusted_manifest_path(path) {
            return Self::rule_signing_status_invalid_trust_root(trust_root_path, e.to_string());
        }

        let contents = match Self::read_trusted_manifest_contents(path) {
            Ok(contents) => contents,
            Err(reason) => {
                return Self::rule_signing_status_invalid_trust_root(trust_root_path, reason);
            }
        };

        let signer = match Self::first_trusted_manifest_signer(&contents) {
            Ok(Some(signer)) => signer,
            Ok(None) => return Self::rule_signing_status_manifest_has_no_signers(trust_root_path),
            Err(reason) => {
                return Self::rule_signing_status_invalid_trust_root(trust_root_path, reason);
            }
        };
        let db_matches = self
            .trusted_signer_db_matches(
                &signer.fingerprint,
                &signer.signer_kind,
                &signer.public_key_hex,
            )
            .unwrap_or(false);

        if !db_matches {
            return Self::rule_signing_status_cache_mismatch(trust_root_path, signer);
        }

        RuleSigningStatus {
            configured: true,
            status: "configured".to_string(),
            signer_kind: Some(signer.signer_kind),
            fingerprint: Some(signer.fingerprint),
            trust_root_path,
            trust_root_ok: true,
            reason: None,
            action: None,
        }
    }

    fn rule_signing_status_no_trust_root() -> RuleSigningStatus {
        RuleSigningStatus {
            configured: false,
            status: "not-configured".to_string(),
            signer_kind: None,
            fingerprint: None,
            trust_root_path: None,
            trust_root_ok: false,
            reason: Some(
                "system trusted signer manifest is unavailable for this state directory"
                    .to_string(),
            ),
            action: Some(
                "run the installer on a supported hardware-backed signing platform".to_string(),
            ),
        }
    }

    fn rule_signing_status_invalid_trust_root(
        trust_root_path: Option<String>,
        reason: String,
    ) -> RuleSigningStatus {
        RuleSigningStatus {
            configured: false,
            status: "invalid".to_string(),
            signer_kind: None,
            fingerprint: None,
            trust_root_path,
            trust_root_ok: false,
            reason: Some(reason),
            action: Some("rerun the installer to repair signer enrollment".to_string()),
        }
    }

    fn rule_signing_status_manifest_has_no_signers(
        trust_root_path: Option<String>,
    ) -> RuleSigningStatus {
        RuleSigningStatus {
            configured: false,
            status: "not-configured".to_string(),
            signer_kind: None,
            fingerprint: None,
            trust_root_path,
            trust_root_ok: true,
            reason: Some("trusted signer manifest contains no signer entries".to_string()),
            action: Some("run the installer to enroll a hardware-backed signer".to_string()),
        }
    }

    fn rule_signing_status_cache_mismatch(
        trust_root_path: Option<String>,
        signer: TrustedManifestSigner,
    ) -> RuleSigningStatus {
        RuleSigningStatus {
            configured: false,
            status: "invalid".to_string(),
            signer_kind: Some(signer.signer_kind),
            fingerprint: Some(signer.fingerprint),
            trust_root_path,
            trust_root_ok: true,
            reason: Some("trusted signer manifest does not match daemon signer cache".to_string()),
            action: Some("rerun the installer to repair signer enrollment".to_string()),
        }
    }

    fn read_trusted_manifest_contents(path: &Path) -> Result<String, String> {
        std::fs::read_to_string(path)
            .map_err(|e| format!("trusted signer manifest unreadable: {e}"))
    }

    fn first_trusted_manifest_signer(
        contents: &str,
    ) -> Result<Option<TrustedManifestSigner>, String> {
        guard_core::first_trusted_signer(contents)
            .map(|signer| {
                signer.map(|signer| TrustedManifestSigner {
                    fingerprint: signer.public_key_sha256,
                    signer_kind: signer.signer_kind,
                    public_key_hex: signer.public_key_x963_hex,
                })
            })
            .map_err(|e| e.to_string())
    }

    fn trusted_manifest_contains(
        &self,
        public_key_sha256: &str,
        signer_kind: &str,
        public_key_x963: Option<&[u8]>,
    ) -> Result<bool, RuleStoreError> {
        let Some(path) = &self.trusted_signers_manifest_path else {
            return Ok(true);
        };
        Self::verify_trusted_manifest_path(path)?;
        let contents = std::fs::read_to_string(path).map_err(|e| {
            RuleStoreError::Signature(format!(
                "trusted signer manifest unreadable at {}: {e}",
                path.display()
            ))
        })?;
        guard_core::trusted_signer_matches(
            &contents,
            public_key_sha256,
            signer_kind,
            public_key_x963,
        )
        .map_err(|e| RuleStoreError::Signature(e.to_string()))
    }

    fn trusted_signer_db_matches(
        &self,
        public_key_sha256: &str,
        signer_kind: &str,
        public_key_hex: &str,
    ) -> Result<bool, RuleStoreError> {
        let public_key = decode_hex(public_key_hex)?;
        let conn = self.reader.lock().expect("rule store reader mutex");
        let count: i64 = conn.query_row(
            "SELECT COUNT(*) FROM trusted_rule_signers
             WHERE public_key_sha256 = ?1 AND signer_kind = ?2 AND public_key_x963 = ?3",
            params![public_key_sha256, signer_kind, public_key],
            |r| r.get(0),
        )?;
        Ok(count == 1)
    }

    fn verify_trusted_manifest_path(path: &Path) -> Result<(), RuleStoreError> {
        let meta = std::fs::symlink_metadata(path).map_err(|e| {
            RuleStoreError::Signature(format!(
                "trusted signer manifest metadata unreadable at {}: {e}",
                path.display()
            ))
        })?;
        if !meta.file_type().is_file() {
            return Err(RuleStoreError::Signature(format!(
                "trusted signer manifest is not a regular file: {}",
                path.display()
            )));
        }
        if meta.uid() != 0 || meta.gid() != 0 || meta.mode() & 0o022 != 0 {
            return Err(RuleStoreError::Signature(format!(
                "trusted signer manifest has unsafe ownership or permissions: {} uid={} gid={} mode={:o}",
                path.display(),
                meta.uid(),
                meta.gid(),
                meta.mode() & 0o777
            )));
        }
        let parent = path.parent().ok_or_else(|| {
            RuleStoreError::Signature(format!(
                "trusted signer manifest has no parent directory: {}",
                path.display()
            ))
        })?;
        let parent_meta = std::fs::symlink_metadata(parent).map_err(|e| {
            RuleStoreError::Signature(format!(
                "trusted signer manifest parent metadata unreadable at {}: {e}",
                parent.display()
            ))
        })?;
        if !parent_meta.file_type().is_dir() {
            return Err(RuleStoreError::Signature(format!(
                "trusted signer manifest parent is not a directory: {}",
                parent.display()
            )));
        }
        if parent_meta.uid() != 0 || parent_meta.gid() != 0 || parent_meta.mode() & 0o022 != 0 {
            return Err(RuleStoreError::Signature(format!(
                "trusted signer manifest parent has unsafe ownership or permissions: {} uid={} gid={} mode={:o}",
                parent.display(),
                parent_meta.uid(),
                parent_meta.gid(),
                parent_meta.mode() & 0o777
            )));
        }
        Ok(())
    }

    /// Count all rows in the rules table (user-approved rules added via `stt-guard approve`).
    /// Used by `StatusReply` handler.
    ///
    /// # Errors
    ///
    /// Returns `SQLite` errors from counting rows.
    ///
    /// # Panics
    ///
    /// Panics if the rule-store reader mutex is poisoned.
    pub fn count_user_rules(&self) -> SqlResult<u64> {
        let conn = self.reader.lock().expect("rule store reader mutex");
        conn.query_row("SELECT COUNT(*) FROM rules", [], |r| r.get::<_, i64>(0))
            .map(|n| u64::try_from(n).unwrap_or(0))
    }

    /// Read all user rules; map each row to an `AllowlistEntry` with tier
    /// `UserDeny` / `UserAllow`. Legacy helper retained for status/tests; snapshot
    /// preparation must use `all_verified_user_rules`.
    ///
    /// # Errors
    ///
    /// Returns `SQLite` errors from reading or mapping rows.
    ///
    /// # Panics
    ///
    /// Panics if the rule-store reader mutex is poisoned.
    pub fn all_user_rules(&self) -> SqlResult<Vec<AllowlistEntry>> {
        let conn = self.reader.lock().expect("rule store reader mutex");
        let mut stmt =
            conn.prepare("SELECT kind, match_type, pattern, reason FROM rules ORDER BY id")?;
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

    /// Read and verify all signed user rules. Any unsigned or tampered user rule
    /// is a fail-closed error; callers must not silently proceed without user
    /// rules when this returns Err.
    ///
    /// # Errors
    ///
    /// Returns `SQLite`, signature verification, or unsigned-rule errors.
    ///
    /// # Panics
    ///
    /// Panics if the rule-store reader mutex is poisoned.
    pub fn all_verified_user_rules(
        &self,
        policy: RuleSignaturePolicy,
    ) -> Result<Vec<AllowlistEntry>, RuleStoreError> {
        let conn = self.reader.lock().expect("rule store reader mutex");
        if let Some(id) = conn
            .query_row(
                "SELECT r.id
                 FROM rules r
                 LEFT JOIN rule_signatures s ON s.rule_id = r.id
                 WHERE s.rule_id IS NULL
                 LIMIT 1",
                [],
                |r| r.get::<_, i64>(0),
            )
            .optional()?
        {
            return Err(RuleStoreError::Signature(format!(
                "unsigned user rule present: rule_id={id}"
            )));
        }
        if let Some(id) = conn
            .query_row(
                "SELECT s.rule_id
                 FROM rule_signatures s
                 LEFT JOIN rules r ON r.id = s.rule_id
                 WHERE r.id IS NULL
                 LIMIT 1",
                [],
                |r| r.get::<_, i64>(0),
            )
            .optional()?
        {
            return Err(RuleStoreError::Signature(format!(
                "orphan rule signature present: rule_id={id}"
            )));
        }
        let total_rules: i64 = conn.query_row("SELECT COUNT(*) FROM rules", [], |r| r.get(0))?;

        let mut stmt = conn.prepare(
            "SELECT
                r.kind, r.match_type, r.pattern, r.reason, r.created_at,
                s.scheme, s.signer_kind, s.public_key_x963, s.public_key_sha256,
                s.signature_der, s.signed_payload_sha256, s.signature_created_at,
                s.origin, s.run_uuid, s.payload_created_at
             FROM rules r
             JOIN rule_signatures s ON s.rule_id = r.id
             ORDER BY r.id",
        )?;
        let rows = stmt.query_map([], Self::verified_rule_row_from_sql)?;

        let mut out = Vec::new();
        let mut verified_rows = 0_i64;
        for row in rows {
            out.push(self.verify_user_rule_row(&conn, row?, policy)?);
            verified_rows += 1;
        }
        if verified_rows != total_rules {
            return Err(RuleStoreError::Signature(format!(
                "verified user rule count mismatch: verified={verified_rows}, rules={total_rules}"
            )));
        }
        Ok(out)
    }

    fn verified_rule_row_from_sql(row: &rusqlite::Row<'_>) -> SqlResult<VerifiedRuleRow> {
        Ok(VerifiedRuleRow {
            kind: row.get(0)?,
            match_type: row.get(1)?,
            pattern: row.get(2)?,
            reason: row.get(3)?,
            created_at: row.get(4)?,
            scheme: row.get(5)?,
            signer_kind: row.get(6)?,
            public_key_x963: row.get(7)?,
            public_key_sha256: row.get(8)?,
            signature_der: row.get(9)?,
            signed_payload_sha256: row.get(10)?,
            signature_created_at_unix_ms: row.get(11)?,
            origin: row.get(12)?,
            run_uuid: row.get(13)?,
            payload_created_at: row.get(14)?,
        })
    }

    fn verify_user_rule_row(
        &self,
        conn: &Connection,
        row: VerifiedRuleRow,
        policy: RuleSignaturePolicy,
    ) -> Result<AllowlistEntry, RuleStoreError> {
        if row.created_at != row.payload_created_at {
            return Err(RuleStoreError::Signature(
                "rule created_at does not match signed payload".into(),
            ));
        }

        let payload = RuleSignaturePayloadV1::new(
            row.kind.clone(),
            row.match_type.clone(),
            row.pattern.clone(),
            row.reason.clone(),
            row.created_at,
            row.origin,
            row.run_uuid,
        );
        let signature = RuleSignatureV1 {
            scheme: row.scheme,
            signer_kind: row.signer_kind,
            public_key_x963: row.public_key_x963,
            public_key_sha256: row.public_key_sha256,
            signature_der: row.signature_der,
            signed_payload_sha256: row.signed_payload_sha256,
            signature_created_at_unix_ms: row.signature_created_at_unix_ms,
        };
        verify_rule_signature(&payload, &signature, policy)
            .map_err(|e| RuleStoreError::Signature(e.to_string()))?;
        self.verify_rule_signer_trusted(conn, &signature)?;

        let kind = Self::parse_rule_kind(&row.kind)?;
        let match_type = Self::parse_match_type(&row.match_type)?;
        let tier = match kind {
            RuleKind::Allow => RuleTier::UserAllow,
            RuleKind::Deny => RuleTier::UserDeny,
        };

        Ok(AllowlistEntry {
            kind,
            tier,
            match_type,
            pattern: row.pattern,
            reason: row.reason,
        })
    }

    fn verify_rule_signer_trusted(
        &self,
        conn: &Connection,
        signature: &RuleSignatureV1,
    ) -> Result<(), RuleStoreError> {
        let trusted_count: i64 = conn.query_row(
            "SELECT COUNT(*) FROM trusted_rule_signers
             WHERE public_key_sha256 = ?1 AND signer_kind = ?2",
            params![
                signature.public_key_sha256.as_str(),
                signature.signer_kind.as_str()
            ],
            |r| r.get(0),
        )?;
        if trusted_count == 1
            && self.trusted_manifest_contains(
                &signature.public_key_sha256,
                &signature.signer_kind,
                Some(&signature.public_key_x963),
            )?
        {
            return Ok(());
        }

        Err(RuleStoreError::Signature(format!(
            "untrusted rule signer: {}",
            signature.public_key_sha256
        )))
    }

    fn parse_rule_kind(kind: &str) -> Result<RuleKind, RuleStoreError> {
        match kind {
            "allow" => Ok(RuleKind::Allow),
            "deny" => Ok(RuleKind::Deny),
            other => Err(RuleStoreError::Signature(format!("invalid kind: {other}"))),
        }
    }

    fn parse_match_type(match_type: &str) -> Result<MatchType, RuleStoreError> {
        match match_type {
            "exact" => Ok(MatchType::Exact),
            "suffix" => Ok(MatchType::Suffix),
            "ip" => Ok(MatchType::Ip),
            other => Err(RuleStoreError::Signature(format!(
                "invalid match_type: {other}"
            ))),
        }
    }

    /// v0.7 — enumerate user rules for `ListRules`.
    ///
    /// Built-in / curated rules are NOT a parameter here: they live on
    /// `DaemonState.curated: Arc<Vec<AllowlistEntry>>` (loaded from
    /// `crates/guard-core/data/{trusted-registry,malicious,suspicious}-*.yaml` via
    /// `crates/guard-daemon/src/curated.rs::load_curated()`). The
    /// caller (`handle_list_rules`) merges them in.
    ///
    /// # Errors
    ///
    /// Returns `SQLite` errors from reading rows.
    ///
    /// # Panics
    ///
    /// Panics if the rule-store reader mutex is poisoned.
    pub fn all_rules_with_source(&self) -> SqlResult<Vec<StoredRule>> {
        let conn = self.reader.lock().expect("rule store reader mutex");
        let mut out: Vec<StoredRule> = Vec::new();

        let mut stmt =
            conn.prepare("SELECT kind, match_type, pattern, reason FROM rules ORDER BY id")?;
        let rows = stmt.query_map([], |row| {
            Ok(StoredRule {
                source: "user".into(),
                kind: row.get::<_, String>(0)?,
                match_type: row.get::<_, String>(1)?,
                pattern: row.get::<_, String>(2)?,
                reason: row.get::<_, String>(3)?,
            })
        })?;
        for r in rows {
            out.push(r?);
        }

        Ok(out)
    }

    // ==================================================================
    // Curated rule overrides — disable/enable built-in rules.
    // ==================================================================

    /// Disable a curated rule by pattern. INSERT OR REPLACE into
    /// `curated_overrides` so repeated calls are idempotent.
    ///
    /// # Errors
    ///
    /// Returns `SQLite` errors from persisting the override.
    ///
    /// # Panics
    ///
    /// Panics if the rule-store mutex is poisoned.
    pub fn disable_curated_rule(&self, pattern: &str, reason: &str) -> SqlResult<()> {
        debug_assert!(!pattern.trim().is_empty(), "pattern must be non-empty");
        debug_assert!(!reason.trim().is_empty(), "reason must be non-empty");
        let conn = self.conn.lock().expect("rule store mutex");
        let now = unix_ms_now();
        conn.execute(
            "INSERT OR REPLACE INTO curated_overrides (pattern, disabled, reason, created_at) \
             VALUES (?1, 1, ?2, ?3)",
            params![pattern, reason, now],
        )?;
        Ok(())
    }

    /// Re-enable a previously disabled curated rule. Returns true if a
    /// row was actually deleted (the rule was disabled), false otherwise.
    ///
    /// # Errors
    ///
    /// Returns `SQLite` errors from deleting the override.
    ///
    /// # Panics
    ///
    /// Panics if the rule-store mutex is poisoned.
    pub fn enable_curated_rule(&self, pattern: &str) -> SqlResult<bool> {
        let conn = self.conn.lock().expect("rule store mutex");
        let deleted = conn.execute(
            "DELETE FROM curated_overrides WHERE pattern = ?1",
            params![pattern],
        )?;
        Ok(deleted > 0)
    }

    /// Return the set of all currently-disabled curated rule patterns.
    /// Used by `PrepareSnapshot` to filter out disabled curated rules.
    ///
    /// # Errors
    ///
    /// Returns `SQLite` errors from reading overrides.
    ///
    /// # Panics
    ///
    /// Panics if the rule-store reader mutex is poisoned.
    pub fn disabled_curated_patterns(&self) -> SqlResult<HashSet<String>> {
        let conn = self.reader.lock().expect("rule store reader mutex");
        let mut stmt = conn.prepare("SELECT pattern FROM curated_overrides WHERE disabled = 1")?;
        let rows = stmt.query_map([], |row| row.get::<_, String>(0))?;
        let mut set = HashSet::new();
        for r in rows {
            set.insert(r?);
        }
        Ok(set)
    }

    /// Check whether a user allow rule already exists for a pattern.
    ///
    /// # Errors
    ///
    /// Returns `SQLite` errors from counting matching rows.
    ///
    /// # Panics
    ///
    /// Panics if the rule-store reader mutex is poisoned.
    pub fn has_user_allow_for(&self, pattern: &str) -> SqlResult<bool> {
        let conn = self.reader.lock().expect("rule store reader mutex");
        let count: i64 = conn.query_row(
            "SELECT COUNT(*) FROM rules WHERE kind = 'allow' AND pattern = ?1",
            params![pattern],
            |r| r.get(0),
        )?;
        Ok(count > 0)
    }
}

#[must_use]
pub fn unix_ms_now() -> i64 {
    let millis = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis();
    i64::try_from(millis).unwrap_or(i64::MAX)
}

fn decode_hex(s: &str) -> Result<Vec<u8>, RuleStoreError> {
    if s.len() % 2 != 0 {
        return Err(RuleStoreError::Signature(
            "trusted signer manifest contains odd-length public key hex".into(),
        ));
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    for pair in s.as_bytes().chunks_exact(2) {
        let hi = hex_value(pair[0])?;
        let lo = hex_value(pair[1])?;
        out.push((hi << 4) | lo);
    }
    Ok(out)
}

fn hex_value(b: u8) -> Result<u8, RuleStoreError> {
    match b {
        b'0'..=b'9' => Ok(b - b'0'),
        b'a'..=b'f' => Ok(b - b'a' + 10),
        b'A'..=b'F' => Ok(b - b'A' + 10),
        _ => Err(RuleStoreError::Signature(
            "trusted signer manifest contains invalid public key hex".into(),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn open_store() -> (TempDir, RuleStore) {
        let tmp = TempDir::new().unwrap();
        let db_path = guard_core::paths::db_path(tmp.path());
        let store = RuleStore::open(&db_path).expect("open");
        (tmp, store)
    }

    #[test]
    fn disable_curated_rule_inserts_override() {
        let (_tmp, store) = open_store();
        store
            .disable_curated_rule("registry.npmjs.org", "suspected compromise")
            .expect("disable");
        let disabled = store.disabled_curated_patterns().expect("read");
        assert!(disabled.contains("registry.npmjs.org"));
    }

    #[test]
    fn disable_curated_rule_is_idempotent() {
        let (_tmp, store) = open_store();
        store
            .disable_curated_rule("registry.npmjs.org", "first reason")
            .expect("disable 1");
        store
            .disable_curated_rule("registry.npmjs.org", "updated reason")
            .expect("disable 2");
        let disabled = store.disabled_curated_patterns().expect("read");
        assert_eq!(disabled.len(), 1);
        assert!(disabled.contains("registry.npmjs.org"));
    }

    #[test]
    fn enable_curated_rule_removes_override() {
        let (_tmp, store) = open_store();
        store
            .disable_curated_rule("registry.npmjs.org", "compromise")
            .expect("disable");
        let was_disabled = store
            .enable_curated_rule("registry.npmjs.org")
            .expect("enable");
        assert!(was_disabled, "should have been disabled");
        let disabled = store.disabled_curated_patterns().expect("read");
        assert!(disabled.is_empty());
    }

    #[test]
    fn enable_curated_rule_not_found() {
        let (_tmp, store) = open_store();
        let was_disabled = store
            .enable_curated_rule("nonexistent.example.com")
            .expect("enable");
        assert!(!was_disabled, "should not have been disabled");
    }

    #[test]
    fn disabled_curated_patterns_returns_empty_when_none() {
        let (_tmp, store) = open_store();
        let disabled = store.disabled_curated_patterns().expect("read");
        assert!(disabled.is_empty());
    }

    #[test]
    fn multiple_disabled_patterns() {
        let (_tmp, store) = open_store();
        store
            .disable_curated_rule("registry.npmjs.org", "reason 1")
            .expect("disable 1");
        store
            .disable_curated_rule("pypi.org", "reason 2")
            .expect("disable 2");
        let disabled = store.disabled_curated_patterns().expect("read");
        assert_eq!(disabled.len(), 2);
        assert!(disabled.contains("registry.npmjs.org"));
        assert!(disabled.contains("pypi.org"));
    }
}
