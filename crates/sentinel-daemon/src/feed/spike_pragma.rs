//! Spike A3: validate whether `rusqlite_migration` accepts a PRAGMA-only
//! migration step (e.g. `M::up("PRAGMA journal_mode = WAL;")`) or whether
//! plan 02's migration 003 must split into DDL-via-migration + WAL-via-runtime
//! (`conn.pragma_update(None, "journal_mode", "WAL")`) per RESEARCH.md
//! Pitfall 5.
//!
//! The two tests below exercise both paths against a fresh tempdir SQLite
//! file. The eprintln output drives the SPIKE-RESULTS.md A3 section's
//! recommendation.

#[test]
fn spike_pragma_only_migration_step_works() {
    use rusqlite::Connection;
    use rusqlite_migration::{M, Migrations};
    use tempfile::tempdir;

    let dir = tempdir().expect("tempdir");
    let db_path = dir.path().join("spike.db");
    let mut conn = Connection::open(&db_path).expect("open");

    let migrations = Migrations::new(vec![
        M::up("CREATE TABLE t (id INTEGER PRIMARY KEY);"),
        M::up("PRAGMA journal_mode = WAL;"),
    ]);
    let migration_result = migrations.to_latest(&mut conn);

    let mode: String = conn
        .query_row("PRAGMA journal_mode", [], |r| r.get(0))
        .expect("query journal_mode");
    eprintln!(
        "PRAGMA-MIGRATION-RESULT: migration_result_ok={} mode={}",
        migration_result.is_ok(),
        mode
    );
    // For the spike, all we need is that the test does not panic — the
    // eprintln captures the actual outcome. Plan 02 branches on the
    // recommendation documented in SPIKE-RESULTS.md.
}

#[test]
fn spike_runtime_pragma_fallback_works() {
    use rusqlite::Connection;
    use tempfile::tempdir;

    let dir = tempdir().expect("tempdir");
    let db_path = dir.path().join("spike2.db");
    let conn = Connection::open(&db_path).expect("open");

    conn.pragma_update(None, "journal_mode", "WAL")
        .expect("pragma_update WAL");
    let mode: String = conn
        .query_row("PRAGMA journal_mode", [], |r| r.get(0))
        .expect("query journal_mode");
    assert_eq!(
        mode.to_lowercase(),
        "wal",
        "WAL must be active after pragma_update"
    );
    eprintln!("RUNTIME-PRAGMA-FALLBACK: journal_mode={}", mode);
}
