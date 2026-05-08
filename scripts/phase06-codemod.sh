#!/usr/bin/env bash
# Phase 06 codemod — rewrite `sentinel run -- <cmd>` test invocations to `sentinel <cmd>`.
#
# Scope:   crates/sentinel-e2e/tests/, crates/sentinel-cli/tests/
# Effect:  removes standalone `.arg("run")` and `.arg("--")` lines that were
#          paired with `run` (the only current occurrences in this tree).
# Trigger: `bash scripts/phase06-codemod.sh` from the workspace root.
# Safety:  idempotent — re-running on an already-codemodded tree is a no-op.
#          The line-anchored regex never matches multi-arg `.args([...])` slices,
#          so `crates/sentinel-e2e/tests/bench_regression.rs` (cargo-bench `--`)
#          is correctly left alone.
#
# Sources: CONTEXT D-08 (one-shot codemod inside Phase 06)
#          RESEARCH §"Codemod > Option 1: two ripgrep + sed passes"

set -euo pipefail

SCOPE=(crates/sentinel-e2e/tests crates/sentinel-cli/tests)

# Use rg if available, fall back to grep.
grep_cmd() {
  if command -v rg >/dev/null 2>&1; then
    rg -l "$@"
  else
    grep -rl "$@"
  fi
}

# Pass 1: remove `.arg("run")` lines (chained or standalone-statement form).
# Match the entire line: leading whitespace + the call + optional trailing
# whitespace, with no other tokens on the line. This protects multi-arg
# `.args([...])` calls from accidental modification.
files_p1=$(grep_cmd '\.arg\("run"\)' "${SCOPE[@]}" 2>/dev/null || true)
if [[ -n "${files_p1}" ]]; then
  echo "${files_p1}" | xargs sed -i.bak -E '
    /^[[:space:]]*\.arg\("run"\)[[:space:]]*$/d
    /^[[:space:]]*cmd\.arg\("run"\);[[:space:]]*$/d
  '
fi

# Pass 2: remove standalone `.arg("--")` lines. In the current tree EVERY
# such occurrence pairs with a `.arg("run")` on the previous line — Pass 1
# has just removed those `run` lines, so the surviving `.arg("--")` lines
# are now orphans of `sentinel run --`. The line-anchored regex protects
# `cargo bench`-style multi-arg slices.
files_p2=$(grep_cmd '\.arg\("--"\)' "${SCOPE[@]}" 2>/dev/null || true)
if [[ -n "${files_p2}" ]]; then
  echo "${files_p2}" | xargs sed -i.bak -E '
    /^[[:space:]]*\.arg\("--"\)[[:space:]]*$/d
    /^[[:space:]]*cmd\.arg\("--"\);[[:space:]]*$/d
  '
fi

# Cleanup BSD-sed backup files.
find "${SCOPE[@]}" -name '*.bak' -delete

# Report
remaining_run=$(grep_cmd '\.arg\("run"\)' "${SCOPE[@]}" 2>/dev/null | wc -l | tr -d ' ')
remaining_dd=$(grep_cmd  '\.arg\("--"\)'  "${SCOPE[@]}" 2>/dev/null | wc -l | tr -d ' ')
echo "Phase 06 codemod complete."
echo "  remaining .arg(\"run\") files: ${remaining_run}"
echo "  remaining .arg(\"--\")  files: ${remaining_dd}"

if [[ "${remaining_run}" -ne 0 ]]; then
  echo "ERROR: Pass 1 left .arg(\"run\") hits behind. Inspect manually." >&2
  exit 2
fi
