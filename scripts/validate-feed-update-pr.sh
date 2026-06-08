#!/usr/bin/env bash
set -euo pipefail

base_ref="${1:-origin/main}"
target="crates/guard-core/data/malicious-ossf-packages.yaml"

changed_files="$(git diff --name-only "$base_ref...HEAD")"

if [ -z "$changed_files" ]; then
  echo "::error::Feed update branch has no changes relative to $base_ref"
  exit 1
fi

unexpected_files="$(
  printf '%s\n' "$changed_files" \
    | awk -v target="$target" '$0 != target { print }'
)"

if [ -n "$unexpected_files" ]; then
  {
    echo "::error::Feed update branch changed files outside $target"
    printf '%s\n' "$unexpected_files"
  } >&2
  exit 1
fi

if ! printf '%s\n' "$changed_files" | grep -qxF "$target"; then
  echo "::error::Feed update branch did not change $target"
  exit 1
fi

cargo test -p guard-daemon --test curated_yaml_tests
