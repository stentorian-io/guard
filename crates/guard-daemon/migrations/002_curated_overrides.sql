-- Curated rule overrides — allows users to disable specific curated
-- (built-in) allow/deny rules when a trusted source is compromised.
--
-- The `pattern` column matches AllowlistEntry.pattern (e.g.
-- "registry.npmjs.org", ".pypi.org"). UNIQUE constraint prevents
-- duplicate entries. To re-enable a rule, DELETE the row.

CREATE TABLE IF NOT EXISTS curated_overrides (
    id         INTEGER PRIMARY KEY,
    pattern    TEXT    NOT NULL UNIQUE,
    disabled   INTEGER NOT NULL DEFAULT 1,
    reason     TEXT    NOT NULL,
    created_at INTEGER NOT NULL
);
