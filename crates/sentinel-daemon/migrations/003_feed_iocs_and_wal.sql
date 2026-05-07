-- Phase 4 plan 04-02 — feed_iocs + feed_metadata tables (D-88 + D-89).
--
-- WAL mode is online-safe in SQLite. Per 04-SPIKE-RESULTS.md A3 (empirically
-- verified Wave 0): a `M::up("PRAGMA journal_mode = WAL;")` migration step
-- silently leaves journal_mode = "delete" because rusqlite_migration wraps each
-- step in an implicit transaction (and `journal_mode = WAL` is incompatible
-- with an open transaction — the change is rolled back).
--
-- Therefore migration 003 contains DDL only. The WAL pragma is applied at
-- runtime via `conn.pragma_update(None, "journal_mode", "WAL")` in
-- `RuleStore::open` AFTER `migrations.to_latest()` returns. A
-- `debug_assert_eq!(mode.to_lowercase(), "wal")` in `RuleStore::open` catches
-- silent regressions.

CREATE TABLE IF NOT EXISTS feed_iocs (
    feed                    TEXT    NOT NULL CHECK (feed IN ('OSV', 'GHSA')),
    advisory_id             TEXT    NOT NULL,
    ecosystem               TEXT    NOT NULL,
    package                 TEXT    NOT NULL,
    versions_json           TEXT    NOT NULL,
    severity                TEXT,
    tag                     TEXT,
    first_seen_ms           INTEGER NOT NULL,
    host_ioc                TEXT,
    schema_version_observed TEXT    NOT NULL,
    PRIMARY KEY (feed, advisory_id, ecosystem, package, host_ioc)
);

CREATE INDEX IF NOT EXISTS idx_feed_iocs_pkg ON feed_iocs(ecosystem, package);
CREATE INDEX IF NOT EXISTS idx_feed_iocs_host ON feed_iocs(host_ioc) WHERE host_ioc IS NOT NULL;

CREATE TABLE IF NOT EXISTS feed_metadata (
    feed                    TEXT PRIMARY KEY CHECK (feed IN ('OSV', 'GHSA')),
    last_pull_ms            INTEGER NOT NULL,
    last_pull_outcome       TEXT NOT NULL CHECK (last_pull_outcome IN
                                ('ok', 'network_error', 'parse_error', 'schema_unknown', 'panic')),
    last_commit_sha         TEXT,
    schema_version_observed TEXT,
    error_message           TEXT,
    record_count            INTEGER NOT NULL DEFAULT 0
);
