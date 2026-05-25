#!/usr/bin/env bash
#
# Check-cache: skip verification phases whose inputs haven't changed.
#
# Stores pass-markers in .git/check-cache/<sha256>. A different content
# fingerprint means a different key — stale entries are pruned automatically.
#
# Usage (source this file, then call the functions):
#   source "$(dirname "$0")/check-cache.sh"
#   if cache_hit "cargo-check" "$(cargo_fingerprint)"; then
#     echo "cached — skipping"
#   else
#     cargo check && cache_mark "cargo-check"
#   fi
#

CACHE_DIR="$(git rev-parse --git-dir 2>/dev/null)/check-cache"
CACHE_MAX_AGE_HOURS=24

_ensure_cache_dir() {
  mkdir -p "$CACHE_DIR" 2>/dev/null || true
}

_cache_key() {
  local phase="$1" fingerprint="$2"
  printf '%s' "${phase}:${fingerprint}" | shasum -a 256 | awk '{print $1}'
}

cache_hit() {
  local phase="$1" fingerprint="$2"
  _ensure_cache_dir
  local key
  key=$(_cache_key "$phase" "$fingerprint")
  [ -f "$CACHE_DIR/$key" ]
}

cache_mark() {
  local phase="$1" fingerprint="$2"
  _ensure_cache_dir
  local key
  key=$(_cache_key "$phase" "$fingerprint")
  date +%s > "$CACHE_DIR/$key"
}

cache_prune() {
  _ensure_cache_dir
  local now cutoff
  now=$(date +%s)
  cutoff=$((now - CACHE_MAX_AGE_HOURS * 3600))
  for f in "$CACHE_DIR"/*; do
    [ -f "$f" ] || continue
    local ts
    ts=$(cat "$f" 2>/dev/null || echo 0)
    if [ "$ts" -lt "$cutoff" ] 2>/dev/null; then
      rm -f "$f"
    fi
  done
}

# ── Fingerprint helpers ────────────────────────────────────────────────────

_head_sha() {
  git rev-parse HEAD 2>/dev/null || echo "no-head"
}

rust_fingerprint() {
  { _head_sha; git diff-index HEAD -- '*.rs' 'Cargo.toml' 'Cargo.lock' 'rust-toolchain.toml' 2>/dev/null; } \
    | shasum -a 256 | awk '{print $1}'
}

linux_ci_lint_fingerprint() {
  { rust_fingerprint
    git diff-index HEAD -- \
      'scripts/pre-commit' \
      'scripts/pre-push' \
      'scripts/ci-linux-lint.sh' \
      'scripts/check-cache.sh' \
      'scripts/lint-test-env-vars.sh' \
      '.github/workflows/ci.yml' \
      '.github/actions/' 2>/dev/null
  } | shasum -a 256 | awk '{print $1}'
}

staged_md_fingerprint() {
  { _head_sha
    git diff --cached --name-only --diff-filter=ACM -- '*.md' 2>/dev/null \
      | sort \
      | xargs -I{} git diff --cached -- {} 2>/dev/null
  } | shasum -a 256 | awk '{print $1}'
}

all_md_fingerprint() {
  { _head_sha; git diff-index HEAD -- '*.md' 2>/dev/null; } \
    | shasum -a 256 | awk '{print $1}'
}

fixture_fingerprint() {
  local fixture="crates/guard-e2e/fixtures/ua-parser-js-0.7.29-sanitized/ua-parser-js-0.7.29-sanitized.tgz"
  local vendor="tools/vendor-ua-parser-js.sh"
  { _head_sha; cat "$fixture" "$vendor" 2>/dev/null; } \
    | shasum -a 256 | awk '{print $1}'
}

e2e_fingerprint() {
  { _head_sha
    git diff-index HEAD -- '*.rs' 'Cargo.toml' 'Cargo.lock' 'rust-toolchain.toml' \
      'crates/guard-e2e/fixtures/' 'crates/guard-e2e/harness/' \
      'crates/guard-core/data/' 'scripts/*.sh' 'tools/' 2>/dev/null
  } | shasum -a 256 | awk '{print $1}'
}

# ── Repo-meta detection ───────────────────────────────────────────────────
#
# Returns 0 (true) when every changed file is "repo meta" — docs, licenses,
# git config, CI yaml, changelog tooling, editor config, etc. — and no
# build/test/runtime code changed.  Used to skip cargo check/test/build
# phases that cannot be affected by these files.
#
# $1 = "staged" (pre-commit: --cached) or "all" (ci-local / pre-push: HEAD)
#
# Files considered repo-meta (non-code):
#   *.md, LICENSE*, SECURITY*, .gitignore, .gitattributes,
#   .github/workflows/*.yml, Brewfile, cliff.toml, .markdownlint*,
#   .editorconfig, docs/*.md (man page sources — groff, not Rust)
#
# Everything else is "code" and causes this to return 1 (false).

_is_repo_meta() {
  local f="$1"
  case "$f" in
    *.md)                       return 0 ;;
    LICENSE*|SECURITY*)         return 0 ;;
    .gitignore|.gitattributes)  return 0 ;;
    .github/workflows/*.yml)    return 0 ;;
    Brewfile|cliff.toml)        return 0 ;;
    .markdownlint*)             return 0 ;;
    .editorconfig)              return 0 ;;
    *)                          return 1 ;;
  esac
}

changes_only_repo_meta() {
  local mode="${1:-all}"
  local files

  if [ "$mode" = "staged" ]; then
    files=$(git diff --cached --name-only --diff-filter=ACMRD 2>/dev/null)
  else
    files=$(git diff-index --name-only HEAD 2>/dev/null)
  fi

  # No changes at all — nothing to skip (let caches handle it)
  [ -n "$files" ] || return 1

  while IFS= read -r f; do
    _is_repo_meta "$f" || return 1
  done <<< "$files"

  return 0
}
