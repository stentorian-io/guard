-- Schema for stt-guard.db — rules + install artifacts.
--
-- WAL mode is applied at runtime via `conn.pragma_update(None, "journal_mode", "WAL")`
-- in `RuleStore::open` AFTER `migrations.to_latest()` returns, because
-- rusqlite_migration wraps each step in an implicit transaction (and the
-- journal_mode pragma is incompatible with an open transaction).

CREATE TABLE IF NOT EXISTS rules (
    id          INTEGER PRIMARY KEY,
    kind        TEXT    NOT NULL CHECK (kind IN ('allow', 'deny')),
    match_type  TEXT    NOT NULL CHECK (match_type IN ('exact', 'suffix', 'ip')),
    pattern     TEXT    NOT NULL,
    reason      TEXT    NOT NULL,
    created_at  INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS install_artifacts (
    artifact_kind     TEXT    NOT NULL CHECK (artifact_kind IN ('launchagent','marker_block','init_script','state_dir','log_dir','binary')),
    target_path       TEXT    NOT NULL,
    content_hash      TEXT,
    installed_at      INTEGER NOT NULL,
    guard_version  TEXT    NOT NULL,
    PRIMARY KEY (artifact_kind, target_path)
);
