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
  local fixture="crates/sentinel-e2e/fixtures/ua-parser-js-0.7.29-sanitized/ua-parser-js-0.7.29-sanitized.tgz"
  local vendor="tools/vendor-ua-parser-js.sh"
  { _head_sha; cat "$fixture" "$vendor" 2>/dev/null; } \
    | shasum -a 256 | awk '{print $1}'
}

e2e_fingerprint() {
  { _head_sha
    git diff-index HEAD -- '*.rs' 'Cargo.toml' 'Cargo.lock' 'rust-toolchain.toml' \
      'crates/sentinel-e2e/fixtures/' 'crates/sentinel-e2e/harness/' \
      'crates/sentinel-core/data/' 2>/dev/null
  } | shasum -a 256 | awk '{print $1}'
}
