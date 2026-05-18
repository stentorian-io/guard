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

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_ROOT"

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

# ── lint-markdown job (ubuntu) ─────────────────────────────────────────────
# Prefer brew's node (declared in Brewfile) over whatever the user's PATH
# resolves to — the latest markdownlint-cli2 needs Node 20+ and some users
# have an older nvm default that shadows brew.
step "Markdown lint"
node_bin="$(command -v node || true)"
if [ -x /opt/homebrew/bin/node ]; then
  node_bin=/opt/homebrew/bin/node
fi
if [ -n "$node_bin" ]; then
  node_dir="$(dirname "$node_bin")"
  PATH="$node_dir:$PATH" npx --yes markdownlint-cli2 "**/*.md" "#target" "#.gsd" \
    || fail "markdown lint"
  pass "markdown lint (node $($node_bin --version))"
else
  warn "node not found — skipping markdown lint"
fi

# ── validation job: fixture SHA check ──────────────────────────────────────
step "Fixture hash check"
fixture=crates/sentinel-e2e/fixtures/ua-parser-js-0.7.29-sanitized/ua-parser-js-0.7.29-sanitized.tgz
test -f "$fixture" || fail "sanitized fixture missing at $fixture"
actual=$(shasum -a 256 "$fixture" | awk '{print $1}')
matches=$(grep -c '^EXPECTED_OUTPUT_SHA256="[a-f0-9]\{64\}"$' \
          tools/vendor-ua-parser-js.sh || true)
[ "$matches" -eq 1 ] || fail "expected one EXPECTED_OUTPUT_SHA256 line in vendor-ua-parser-js.sh, found $matches"
pinned=$(grep '^EXPECTED_OUTPUT_SHA256="[a-f0-9]\{64\}"$' tools/vendor-ua-parser-js.sh \
         | sed -E 's/^EXPECTED_OUTPUT_SHA256="([a-f0-9]{64})"$/\1/')
[ "$actual" = "$pinned" ] || fail "fixture hash mismatch (on-disk $actual vs pinned $pinned)"
pass "fixture matches pinned hash"

# ── ubuntu jobs via act (optional) ─────────────────────────────────────────
if [ "$USE_ACT" -eq 1 ]; then
  if command -v act >/dev/null; then
    step "Ubuntu jobs via act (lint-markdown)"
    # Only run the lint-markdown job — pr-title needs a PR context that act
    # can't synthesise cleanly. The pre-commit hook covers conventional-commit
    # validation for local commits.
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

step "cargo build --workspace --release"
cargo build --workspace --release || fail "cargo build"
pass "cargo build"

E2E_TESTS=(
  "ua_parser_js_demo:VAL-01 ua-parser-js@0.7.29 demo"
  "workers_dev_validation:VAL-02 workers.dev allowlist-bleed"
  "failure_modes_daemon_killed:VAL-04 D-09 daemon-killed mid-run"
  "failure_modes_corrupt_snapshot:VAL-04 D-12 corrupt snapshot"
  "failure_modes_stale_feed:VAL-04 D-11 stale feed"
  "failure_modes_hardened_exec:VAL-04 D-10 hardened-binary exec gap"
)

for entry in "${E2E_TESTS[@]}"; do
  test_name="${entry%%:*}"
  label="${entry#*:}"
  step "$label"
  cargo test -p sentinel-e2e --test "$test_name" --release -- --nocapture \
    || fail "$label"
  pass "$label"
done

echo -e "\n${GREEN}${BOLD}All CI checks passed locally.${RESET}"
