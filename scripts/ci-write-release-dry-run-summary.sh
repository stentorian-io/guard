#!/usr/bin/env bash
set -euo pipefail

: "${GITHUB_STEP_SUMMARY:?GITHUB_STEP_SUMMARY is required}"

tag="${1:?usage: ci-write-release-dry-run-summary.sh <tag>}"

{
  echo "## Dry Run Summary"
  echo "**Tag:** $tag"
  echo "**Artifacts:**"
  ls -lh artifacts/
  echo "**Release metadata:**"
  cat artifacts/release-meta.json
} >> "$GITHUB_STEP_SUMMARY"
