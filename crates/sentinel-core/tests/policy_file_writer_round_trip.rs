//! Round-trip and append fixture tests for `.sentinel.toml` policy_file_writer.
//!
//! Wave-0 spike (Phase 3 plan 03-01): verifies A3 from RESEARCH.md.
//! toml_edit round-trips an existing .sentinel.toml byte-identically when no rule is added.

use sentinel_core::policy_file_writer::{WriteError, append_rule};

const FIXTURE: &str = "# Top-level comment.\n\
version = 1\n\
\n\
[[rules]]\n\
kind = \"allow\"\n\
match = \"suffix\"\n\
pattern = \".example.com\"\n\
reason = \"existing\"\n";

#[test]
fn appends_rule_preserving_existing_content() {
    let result = append_rule(FIXTURE, "allow", "exact", "foo.example.com", "test")
        .expect("append_rule should succeed");

    // Original comment preserved at byte 0
    assert!(
        result.starts_with("# Top-level comment.\n"),
        "output should start with the original comment; got:\n{result}"
    );

    // Original rule's pattern still present
    assert!(
        result.contains("pattern = \".example.com\""),
        "original rule pattern should still be present; got:\n{result}"
    );

    // New rule's pattern present
    assert!(
        result.contains("pattern = \"foo.example.com\""),
        "new rule pattern should be present; got:\n{result}"
    );
}

#[test]
fn idempotent_round_trip_no_rule_added() {
    // A3 verification: parse+to_string with NO append must produce byte-identical output.
    // If this fails, toml_edit reformats and R-03 mitigation is needed.
    let doc = FIXTURE
        .parse::<toml_edit::DocumentMut>()
        .expect("fixture must parse");
    let round_tripped = doc.to_string();
    assert_eq!(
        round_tripped, FIXTURE,
        "toml_edit round-trip is NOT byte-identical (A3 unverified)"
    );
}

#[test]
fn creates_rules_array_when_absent() {
    let input = "version = 1\n";
    let result =
        append_rule(input, "deny", "suffix", ".evil.example.com", "block exfil")
            .expect("append_rule should succeed on version-only input");

    assert!(
        result.contains("[[rules]]"),
        "output should contain [[rules]] array of tables; got:\n{result}"
    );
    assert!(
        result.contains("pattern = \".evil.example.com\""),
        "output should contain the new rule pattern; got:\n{result}"
    );
    assert!(
        result.contains("kind = \"deny\""),
        "output should contain kind = \"deny\"; got:\n{result}"
    );
}

#[test]
fn parse_error_on_malformed_toml() {
    // Truncated table header is invalid TOML
    let input = "version = 1\n[[rules\n";
    let err = append_rule(input, "allow", "exact", "x.example.com", "test")
        .expect_err("should fail on malformed TOML");
    assert!(
        matches!(err, WriteError::ParseError(_)),
        "expected WriteError::ParseError, got: {err:?}"
    );
}

#[test]
fn preserves_unrelated_keys() {
    let input = "version = 1\n# my comment\n\n[future_section]\nfoo = 42\n";
    let result = append_rule(input, "allow", "exact", "api.example.com", "test")
        .expect("append_rule should succeed");

    assert!(
        result.contains("[future_section]"),
        "output should preserve [future_section]; got:\n{result}"
    );
    assert!(
        result.contains("foo = 42"),
        "output should preserve foo = 42; got:\n{result}"
    );
}
