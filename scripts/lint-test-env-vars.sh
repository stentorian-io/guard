#!/usr/bin/env bash
set -euo pipefail

# CI lint: ensure SENTINEL_TEST_* env vars never appear in production source.
#
# Scans all .rs files in crate src/ directories (excluding sentinel-e2e and
# #[cfg(test)] module boundaries). Exits non-zero if any SENTINEL_TEST_
# reference is found in production code.
#
# Exception: sentinel-hook's env_scrub.rs and lib.rs reference
# SENTINEL_TEST_MARKER by design — the hook must read it at ctor time and
# scrub it from child processes. Only SENTINEL_TEST_MARKER is allowed there;
# any other SENTINEL_TEST_* in those files will still fail.

cd "$(git rev-parse --show-toplevel)"

errors=0

while IFS= read -r file; do
    # Skip the e2e crate entirely — it's all test code
    case "$file" in
        crates/sentinel-e2e/*) continue ;;
    esac

    # Strip #[cfg(test)] mod blocks (rough heuristic: from #[cfg(test)] to end of file)
    # and check the remainder for SENTINEL_TEST_
    cfg_test_line=$(grep -n '#\[cfg(test)\]' "$file" | head -1 | cut -d: -f1 || true)
    if [ -n "$cfg_test_line" ]; then
        content=$(head -n "$((cfg_test_line - 1))" "$file")
    else
        content=$(cat "$file")
    fi

    # In sentinel-hook src, SENTINEL_TEST_MARKER is allowed (production reads it).
    # Filter those out, then check for any remaining SENTINEL_TEST_ references.
    case "$file" in
        crates/sentinel-hook/src/*)
            matches=$(echo "$content" | grep -n 'SENTINEL_TEST_' | grep -v 'SENTINEL_TEST_MARKER' || true)
            ;;
        *)
            matches=$(echo "$content" | grep -n 'SENTINEL_TEST_' || true)
            ;;
    esac

    if [ -n "$matches" ]; then
        echo "ERROR: SENTINEL_TEST_ in production code: $file"
        echo "$matches" | sed 's/^/  /'
        errors=$((errors + 1))
    fi
done < <(find crates/*/src -name '*.rs' -type f)

if [ "$errors" -gt 0 ]; then
    echo ""
    echo "FAIL: $errors file(s) reference SENTINEL_TEST_* outside test code."
    echo "Test env vars must only appear in crates/sentinel-e2e/, #[cfg(test)] modules,"
    echo "or as SENTINEL_TEST_MARKER in sentinel-hook (allowed by design)."
    exit 1
fi

echo "OK: no SENTINEL_TEST_* references in production source."
