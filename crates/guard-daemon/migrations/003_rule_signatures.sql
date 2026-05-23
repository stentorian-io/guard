CREATE TABLE IF NOT EXISTS rule_signatures (
    rule_id                 INTEGER PRIMARY KEY REFERENCES rules(id) ON DELETE CASCADE,
    scheme                  TEXT    NOT NULL,
    signer_kind             TEXT    NOT NULL,
    public_key_x963         BLOB    NOT NULL,
    public_key_sha256       TEXT    NOT NULL,
    signature_der           BLOB    NOT NULL,
    signed_payload_sha256   TEXT    NOT NULL,
    signature_created_at    INTEGER NOT NULL,
    origin                  TEXT    NOT NULL,
    run_uuid                TEXT,
    payload_created_at      INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS trusted_rule_signers (
    public_key_sha256       TEXT PRIMARY KEY,
    signer_kind             TEXT    NOT NULL,
    public_key_x963         BLOB    NOT NULL,
    enrolled_at             INTEGER NOT NULL,
    label                   TEXT    NOT NULL
);
