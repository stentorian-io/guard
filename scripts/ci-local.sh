#!/usr/bin/env bash
#
# Run the CI workflow's checks locally — same commands as
# .github/workflows/validation.yml, no GH minutes consumed.
#
# Usage:
#   scripts/ci-local.sh             # full validation (build + 6 e2e tests)
#   scripts/ci-local.sh --quick     # skip cargo build + e2e (lint + fixture only)
#   scripts/ci-local.sh --no-act    # skip act for the ubuntu jobs
#
# Skip the heavy stuff in a hook: CI_LOCAL_SKIP_E2E=1
#
set -euo pipefail

REPO_ROOT="$(git rev-parse --show-toplevel)"
cd "$REPO_ROOT"
source "$REPO_ROOT/scripts/check-cache.sh"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BOLD='\033[1m'
RESET='\033[0m'

QUICK=0
USE_ACT=1
for arg in "$@"; do
  case "$arg" in
    --quick)  QUICK=1 ;;
    --no-act) USE_ACT=0 ;;
    *)        echo "unknown flag: $arg" >&2; exit 64 ;;
  esac
done

step() { echo -e "\n${BOLD}── $1 ──${RESET}"; }
pass() { echo -e "${GREEN}✓${RESET} $1"; }
fail() { echo -e "${RED}${BOLD}FAIL: $1${RESET}" >&2; exit 1; }
warn() { echo -e "${YELLOW}⚠${RESET} $1"; }
skip() { echo -e "${GREEN}✓${RESET} $1 ${BOLD}(cached)${RESET}"; }

cache_prune

# ── lint-markdown job (ubuntu) ─────────────────────────────────────────────
step "Markdown lint"
node_bin="$(command -v node || true)"
if [ -x /opt/homebrew/bin/node ]; then
  node_bin=/opt/homebrew/bin/node
fi
if [ -n "$node_bin" ]; then
  fp=$(all_md_fingerprint)
  if cache_hit "ci-local:mdlint" "$fp"; then
    skip "markdown lint"
  else
    node_dir="$(dirname "$node_bin")"
    PATH="$node_dir:$PATH" npx --yes markdownlint-cli2 "**/*.md" "#target" "#.gsd" \
      || fail "markdown lint"
    cache_mark "ci-local:mdlint" "$fp"
    pass "markdown lint (node $($node_bin --version))"
  fi
else
  warn "node not found — skipping markdown lint"
fi

# ── validation job: fixture SHA check ──────────────────────────────────────
step "Fixture hash check"
fp=$(fixture_fingerprint)
if cache_hit "ci-local:fixture" "$fp"; then
  skip "fixture hash check"
else
  fixture=crates/sentinel-e2e/fixtures/ua-parser-js-0.7.29-sanitized/ua-parser-js-0.7.29-sanitized.tgz
  test -f "$fixture" || fail "sanitized fixture missing at $fixture"
  actual=$(shasum -a 256 "$fixture" | awk '{print $1}')
  matches=$(grep -c '^EXPECTED_OUTPUT_SHA256="[a-f0-9]\{64\}"$' \
            tools/vendor-ua-parser-js.sh || true)
  [ "$matches" -eq 1 ] || fail "expected one EXPECTED_OUTPUT_SHA256 line in vendor-ua-parser-js.sh, found $matches"
  pinned=$(grep '^EXPECTED_OUTPUT_SHA256="[a-f0-9]\{64\}"$' tools/vendor-ua-parser-js.sh \
           | sed -E 's/^EXPECTED_OUTPUT_SHA256="([a-f0-9]{64})"$/\1/')
  [ "$actual" = "$pinned" ] || fail "fixture hash mismatch (on-disk $actual vs pinned $pinned)"
  cache_mark "ci-local:fixture" "$fp"
  pass "fixture matches pinned hash"
fi

# ── ubuntu jobs via act (optional) ─────────────────────────────────────────
if [ "$USE_ACT" -eq 1 ]; then
  if command -v act >/dev/null; then
    step "Ubuntu jobs via act (lint-markdown)"
    act push --job lint-markdown --quiet 2>&1 \
      || fail "act lint-markdown failed"
    pass "act lint-markdown"
  else
    warn "act not installed — skipping ubuntu-job parity check (brew install act)"
  fi
fi

# ── heavy validation: release build + 6 e2e tests ──────────────────────────
if [ "$QUICK" -eq 1 ] || [ "${CI_LOCAL_SKIP_E2E:-0}" -eq 1 ]; then
  warn "skipping cargo build + e2e (--quick or CI_LOCAL_SKIP_E2E=1)"
  echo -e "\n${GREEN}${BOLD}Quick checks passed.${RESET}"
  exit 0
fi

fp=$(e2e_fingerprint)

step "cargo build --workspace --release"
if cache_hit "ci-local:cargo-build" "$fp"; then
  skip "cargo build"
else
  cargo build --workspace --release || fail "cargo build"
  cache_mark "ci-local:cargo-build" "$fp"
  pass "cargo build"
fi

E2E_TESTS=(
  "ua_parser_js_demo:VAL-01 ua-parser-js@0.7.29 demo"
  "workers_dev_validation:VAL-02 workers.dev allowlist-bleed"
  "failure_modes_daemon_killed:VAL-04 D-09 daemon-killed mid-run"
  "failure_modes_corrupt_snapshot:VAL-04 D-12 corrupt snapshot"
  "failure_modes_stale_feed:VAL-04 D-11 stale feed"
  "failure_modes_hardened_exec:VAL-04 D-10 hardened-binary exec gap"
)

if cache_hit "ci-local:e2e-all" "$fp"; then
  skip "e2e tests (all 6)"
else
  for entry in "${E2E_TESTS[@]}"; do
    test_name="${entry%%:*}"
    label="${entry#*:}"
    step "$label"
    cargo test -p sentinel-e2e --test "$test_name" --release -- --nocapture \
      || fail "$label"
    pass "$label"
  done
  cache_mark "ci-local:e2e-all" "$fp"
fi

echo -e "\n${GREEN}${BOLD}All CI checks passed locally.${RESET}"
