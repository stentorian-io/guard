-- Phase 2 plan 02-03 — initial schema.
--
-- POL-01: persistent rule store. Phase 2 ships the schema + read path.
-- The `sentinel approve` CLI (CLI-04, Phase 3) will write to `rules`.
-- The `sentinel trust-policy` CLI (D-38, plan 02-06) writes to
-- `trusted_policy_files`.
--
-- D-28: machine-wide rules only — no `scope` column.
-- D-37: first-encounter trust model — PRIMARY KEY includes sha256 so
-- modifying the file requires re-trust.

CREATE TABLE IF NOT EXISTS rules (
    id          INTEGER PRIMARY KEY,
    kind        TEXT    NOT NULL CHECK (kind IN ('allow', 'deny')),
    match_type  TEXT    NOT NULL CHECK (match_type IN ('exact', 'suffix', 'ip')),
    pattern     TEXT    NOT NULL,
    reason      TEXT    NOT NULL,
    created_at  INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS trusted_policy_files (
    path        TEXT    NOT NULL,
    sha256      TEXT    NOT NULL,
    trusted_at  INTEGER NOT NULL,
    trusted_via TEXT    NOT NULL CHECK (trusted_via IN ('cli', 'prompt')),
    PRIMARY KEY (path, sha256)
);
