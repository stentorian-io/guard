#!/usr/bin/env bash
set -euo pipefail

# CI lint: ensure STT_GUARD_TEST_* env vars never appear in production source.
#
# Scans all .rs files in crate src/ directories (excluding guard-e2e and
# #[cfg(test)] module boundaries). Exits non-zero if any STT_GUARD_TEST_
# reference is found in production code.
#
# Exception: guard-hook's env_scrub.rs and lib.rs reference
# STT_GUARD_TEST_MARKER by design — the hook must read it at ctor time and
# scrub it from child processes. Only STT_GUARD_TEST_MARKER is allowed there;
# any other STT_GUARD_TEST_* in those files will still fail.

cd "$(git rev-parse --show-toplevel)"

errors=0

while IFS= read -r file; do
    # Skip the e2e crate entirely — it's all test code
    case "$file" in
        crates/guard-e2e/*) continue ;;
    esac

    # Strip #[cfg(test)] mod blocks (rough heuristic: from #[cfg(test)] to end of file)
    # and check the remainder for STT_GUARD_TEST_
    cfg_test_line=$(grep -n '#\[cfg(test)\]' "$file" | head -1 | cut -d: -f1 || true)
    if [ -n "$cfg_test_line" ]; then
        content=$(head -n "$((cfg_test_line - 1))" "$file")
    else
        content=$(cat "$file")
    fi

    # In guard-hook src, STT_GUARD_TEST_MARKER is allowed (production reads it).
    # Filter those out, then check for any remaining STT_GUARD_TEST_ references.
    case "$file" in
        crates/guard-hook/src/*)
            matches=$(echo "$content" | grep -n 'STT_GUARD_TEST_' | grep -v 'STT_GUARD_TEST_MARKER' || true)
            ;;
        *)
            matches=$(echo "$content" | grep -n 'STT_GUARD_TEST_' || true)
            ;;
    esac

    if [ -n "$matches" ]; then
        echo "ERROR: STT_GUARD_TEST_ in production code: $file"
        echo "$matches" | sed 's/^/  /'
        errors=$((errors + 1))
    fi
done < <(find crates/*/src -name '*.rs' -type f)

if [ "$errors" -gt 0 ]; then
    echo ""
    echo "FAIL: $errors file(s) reference STT_GUARD_TEST_* outside test code."
    echo "Test env vars must only appear in crates/guard-e2e/, #[cfg(test)] modules,"
    echo "or as STT_GUARD_TEST_MARKER in guard-hook (allowed by design)."
    exit 1
fi

echo "OK: no STT_GUARD_TEST_* references in production source."
