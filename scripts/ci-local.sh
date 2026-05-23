#!/usr/bin/env bash
#
# Run local equivalents of the split PR/code validation workflows, with no GH
# minutes consumed. Full local CI follows .github/workflows/code-validation.yml;
# act is only used for the cheap .github/workflows/pr-validation.yml gate.
#
# Usage:
#   scripts/ci-local.sh             # code-validation parity (lint + build + tests + e2e)
#   scripts/ci-local.sh --quick     # skip code-validation build/tests (lint + fixture only)
#   scripts/ci-local.sh --no-act    # skip act for the cheap PR-validation gate
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

# ── 0. Detect repo-meta-only changes (skip build/test when nothing compiled changes)
REPO_META_ONLY=0
if changes_only_repo_meta all; then
  REPO_META_ONLY=1
fi

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
  fixture=crates/guard-e2e/fixtures/ua-parser-js-0.7.29-sanitized/ua-parser-js-0.7.29-sanitized.tgz
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

# ── lint-unused-deps (cargo-machete — stable toolchain, no compilation) ────
if [ "$REPO_META_ONLY" -eq 1 ]; then
  skip "cargo-machete (repo-meta-only change)"
else
  step "Unused dependency lint"
  fp=$(rust_fingerprint)
  if cache_hit "ci-local:machete" "$fp"; then
    skip "cargo-machete"
  else
    if command -v cargo-machete >/dev/null; then
      cargo machete --with-metadata || fail "cargo-machete"
      cache_mark "ci-local:machete" "$fp"
      pass "cargo-machete"
    else
      warn "cargo-machete not found — skipping (cargo install cargo-machete)"
    fi
  fi
fi

# ── PR validation gate via act (optional) ──────────────────────────────────
if [ "$USE_ACT" -eq 1 ]; then
  if command -v act >/dev/null; then
    step "PR validation via act (lint-markdown)"
    event_file="$(mktemp)"
    trap 'rm -f "$event_file"' EXIT
    cat > "$event_file" <<'JSON'
{"repository":{"default_branch":"main","full_name":"stentorian-io/guard"},"pull_request":{"number":29,"base":{"ref":"main","repo":{"full_name":"stentorian-io/guard"}},"head":{"ref":"release-infra","repo":{"full_name":"stentorian-io/guard"}}}}
JSON
    act pull_request --workflows .github/workflows/pr-validation.yml --job lint-markdown --eventpath "$event_file" --quiet 2>&1 \
      || fail "act lint-markdown failed"
    pass "act lint-markdown"
  else
    warn "act not installed — skipping ubuntu-job parity check (brew install act)"
  fi
fi

# ── code-validation workflow parity ───────────────────────────────────────
if [ "$QUICK" -eq 1 ] || [ "${CI_LOCAL_SKIP_E2E:-0}" -eq 1 ] || [ "$REPO_META_ONLY" -eq 1 ]; then
  if [ "$REPO_META_ONLY" -eq 1 ]; then
    warn "skipping code-validation build/tests (repo-meta-only change)"
  else
    warn "skipping code-validation build/tests (--quick or CI_LOCAL_SKIP_E2E=1)"
  fi
  echo -e "\n${GREEN}${BOLD}Quick checks passed.${RESET}"
  exit 0
fi

fp=$(e2e_fingerprint)

step "code-validation lint: test env var hygiene"
scripts/lint-test-env-vars.sh || fail "lint test env var hygiene"
pass "lint test env var hygiene"

step "code-validation build: cargo build --workspace --release"
if cache_hit "ci-local:cargo-build" "$fp"; then
  skip "cargo build"
else
  cargo build --workspace --release || fail "cargo build"
  cache_mark "ci-local:cargo-build" "$fp"
  pass "cargo build"
fi

step "code-validation unit tests"
cargo test --workspace --exclude guard-e2e --lib --bins --quiet \
  || fail "cargo test unit targets"
pass "cargo test unit targets"

step "code-validation integration tests"
cargo test --workspace --exclude guard-e2e --tests --quiet \
  || fail "cargo test integration targets"
pass "cargo test integration targets"

# E2E tests skipped due to known pre-existing issues:
#   failure_modes_daemon_killed — step-1 hostname connect fails in CI harness (peer auth)
E2E_TESTS=(
  "ua_parser_js_demo:VAL-01 ua-parser-js@0.7.29 demo"
  "workers_dev_validation:VAL-02 workers.dev allowlist-bleed"
  "failure_modes_corrupt_snapshot:VAL-04 D-12 corrupt snapshot"
  "failure_modes_hardened_exec:VAL-04 D-10 hardened-binary exec gap"
)

if cache_hit "ci-local:e2e-all" "$fp"; then
  skip "e2e tests (all ${#E2E_TESTS[@]})"
else
  for entry in "${E2E_TESTS[@]}"; do
    test_name="${entry%%:*}"
    label="${entry#*:}"
    step "code-validation e2e: $label"
    cargo test -p guard-e2e --test "$test_name" --release -- --nocapture \
      || fail "$label"
    pass "$label"
  done
  cache_mark "ci-local:e2e-all" "$fp"
fi

# Privileged install validation mutates system install paths and requires
# non-interactive sudo. Keep it explicit for developer machines; CI runs the
# same test with STT_GUARD_E2E_PRIVILEGED_INSTALL=1.
PRIVILEGED_VAL05_RAN=0
if [ "${CI_LOCAL_PRIVILEGED_INSTALL:-0}" -eq 1 ]; then
  PRIVILEGED_VAL05_RAN=1
  step "code-validation e2e: VAL-05 privileged init and install health"
  STT_GUARD_E2E_PRIVILEGED_INSTALL=1 \
    cargo test -p guard-e2e --test hardened_install_health --release -- --nocapture \
    || fail "VAL-05 privileged init and install health"
  pass "VAL-05 privileged init and install health"
else
  warn "skipping code-validation e2e: VAL-05 privileged install health (set CI_LOCAL_PRIVILEGED_INSTALL=1 and ensure sudo -n works)"
fi

warn "skipping code-validation secret scan locally (GitHub runs trufflehog on PR range)"

if [ "$PRIVILEGED_VAL05_RAN" -eq 1 ]; then
  echo -e "\n${GREEN}${BOLD}All CI checks passed locally.${RESET}"
else
  echo -e "\n${GREEN}${BOLD}Non-privileged CI checks passed locally; VAL-05 was skipped.${RESET}"
fi
