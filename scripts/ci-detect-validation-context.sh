#!/usr/bin/env bash
set -euo pipefail

: "${GITHUB_EVENT_NAME:?GITHUB_EVENT_NAME is required}"
: "${GITHUB_OUTPUT:?GITHUB_OUTPUT is required}"

if [ "$GITHUB_EVENT_NAME" = "schedule" ]; then
  {
    echo "code=false"
    echo "lockfile=true"
    echo "markdown=false"
    echo "base="
    echo "head="
    echo "is_pr=false"
  } >> "$GITHUB_OUTPUT"
  exit 0
fi

base_ref="${1:-upstream/main}"
changed=$(git diff --name-only "$base_ref...HEAD")
printf 'Changed files:\n%s\n' "$changed"

code=false
lockfile=false
markdown=false
while IFS= read -r path; do
  [ -n "$path" ] || continue
  case "$path" in
    *.rs|*/Cargo.toml|Cargo.toml|*/Cargo.lock|Cargo.lock|rust-toolchain.toml|crates/guard-e2e/fixtures/*|crates/guard-e2e/harness/*|crates/guard-core/data/*|scripts/*.sh|tools/*)
      code=true
      ;;
  esac
  case "$path" in
    */Cargo.toml|Cargo.toml|*/Cargo.lock|Cargo.lock|rust-toolchain.toml)
      lockfile=true
      ;;
  esac
  case "$path" in
    *.md)
      markdown=true
      ;;
  esac
done <<< "$changed"

base=$(git merge-base "$base_ref" HEAD)
head=$(git rev-parse HEAD)

{
  echo "code=$code"
  echo "lockfile=$lockfile"
  echo "markdown=$markdown"
  echo "base=$base"
  echo "head=$head"
  echo "is_pr=true"
} >> "$GITHUB_OUTPUT"

echo "Secret scan range: $base..$head"
