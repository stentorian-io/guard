#!/usr/bin/env bash
#
# Run local equivalents of the split PR/code validation workflows, with no
# GitHub Actions minutes consumed. The default path mirrors the
# .github/workflows/code-validation.yml pull_request path end to end: lint,
# build, unit tests, integration tests, e2e tests, secret scan, and dependency
# CVE audit when lockfiles/toolchain inputs changed.
#
# Usage:
#   scripts/ci-local.sh             # code-validation parity, fully local
#   scripts/ci-local.sh --quick     # skip code-validation build/tests/audit (lint + fixture only)
#   scripts/ci-local.sh --no-act    # skip act for the cheap PR-validation gate
#   scripts/ci-local.sh --no-privileged
#                                  # skip VAL-05 on developer machines
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
RUN_PRIVILEGED=1
for arg in "$@"; do
  case "$arg" in
    --quick)         QUICK=1 ;;
    --no-act)        USE_ACT=0 ;;
    --no-privileged) RUN_PRIVILEGED=0 ;;
    *)               echo "unknown flag: $arg" >&2; exit 64 ;;
  esac
done

step() { echo -e "\n${BOLD}── $1 ──${RESET}"; }
pass() { echo -e "${GREEN}✓${RESET} $1"; }
fail() { echo -e "${RED}${BOLD}FAIL: $1${RESET}" >&2; exit 1; }
warn() { echo -e "${YELLOW}⚠${RESET} $1"; }
skip() { echo -e "${GREEN}✓${RESET} $1 ${BOLD}(cached)${RESET}"; }
cache_enabled() { [ "${CI_LOCAL_USE_CACHE:-0}" -eq 1 ]; }

cache_prune

TMP_FILES=()
cleanup_tmp_files() {
  for f in "${TMP_FILES[@]+"${TMP_FILES[@]}"}"; do
    rm -f "$f"
  done
}
cleanup_on_exit() {
  cleanup_val05_sudoers
  cleanup_tmp_files
}
trap cleanup_on_exit EXIT

mktemp_tracked() {
  local f
  f="$(mktemp)"
  TMP_FILES+=("$f")
  printf '%s\n' "$f"
}

VAL05_SUDOERS_DROPIN=""
VAL05_SUDOERS_INSTALLED=0

sudoers_escape_path() {
  printf '%s' "$1" | sed 's/[\\: ,=]/\\&/g'
}

write_val05_sudoers() {
  local out="$1"
  local user="$2"
  local cli_path watchdog_src
  cli_path="$(sudoers_escape_path "$REPO_ROOT/target/release/stt-guard")"
  watchdog_src="$(sudoers_escape_path "$REPO_ROOT/target/release/stt-guard-watchdog")"

  cat >"$out" <<EOF
$user ALL=(root) NOPASSWD: $cli_path init --yes
$user ALL=(root) NOPASSWD: /bin/launchctl bootout system/io.stentorian.guard.daemon
$user ALL=(root) NOPASSWD: /bin/rm -f /Library/LaunchDaemons/io.stentorian.guard.daemon.plist
$user ALL=(root) NOPASSWD: /bin/rm -rf /usr/local/libexec/stt-guard
$user ALL=(root) NOPASSWD: /bin/rm -rf /Library/Application\ Support/Stentorian\ Guard
$user ALL=(root) NOPASSWD: /bin/rm -rf /var/log/stt-guard
$user ALL=(root) NOPASSWD: /bin/chmod 666 /usr/local/libexec/stt-guard/stt-guard-hook.dylib
$user ALL=(root) NOPASSWD: /bin/chmod 644 /usr/local/libexec/stt-guard/stt-guard-hook.dylib
$user ALL=(root) NOPASSWD: /bin/sh -c *
$user ALL=(root) NOPASSWD: /bin/cp * /Library/LaunchDaemons/io.stentorian.guard.daemon.plist
$user ALL=(root) NOPASSWD: /usr/sbin/chown root\:wheel /Library/LaunchDaemons/io.stentorian.guard.daemon.plist
$user ALL=(root) NOPASSWD: /bin/chmod 644 /Library/LaunchDaemons/io.stentorian.guard.daemon.plist
$user ALL=(root) NOPASSWD: /bin/rm -f /usr/local/libexec/stt-guard/stt-guard-watchdog
$user ALL=(root) NOPASSWD: /bin/ln -s /usr/local/libexec/stt-guard/stt-guard-daemon /usr/local/libexec/stt-guard/stt-guard-watchdog
$user ALL=(root) NOPASSWD: /bin/cp $watchdog_src /usr/local/libexec/stt-guard/stt-guard-watchdog
$user ALL=(root) NOPASSWD: /usr/sbin/chown root\:wheel /usr/local/libexec/stt-guard/stt-guard-watchdog
$user ALL=(root) NOPASSWD: /bin/chmod 755 /usr/local/libexec/stt-guard/stt-guard-watchdog
$user ALL=(root) NOPASSWD: /bin/rm -f /etc/sudoers.d/stt-guard-val05-$user
EOF
}

install_val05_sudoers() {
  local user tmp
  user="$(id -un)"
  tmp="$(mktemp_tracked)"
  VAL05_SUDOERS_DROPIN="/etc/sudoers.d/stt-guard-val05-$user"

  write_val05_sudoers "$tmp" "$user"
  visudo -cf "$tmp" >/dev/null || fail "generated VAL-05 sudoers file is invalid"

  step "Install temporary sudoers rule for VAL-05"
  echo "Installing $VAL05_SUDOERS_DROPIN; it will be removed automatically on exit."
  sudo install -o root -g wheel -m 0440 "$tmp" "$VAL05_SUDOERS_DROPIN" \
    || fail "install temporary VAL-05 sudoers rule"
  VAL05_SUDOERS_INSTALLED=1
  sudo visudo -cf /etc/sudoers >/dev/null \
    || fail "system sudoers validation failed after installing VAL-05 rule"
}

cleanup_val05_sudoers() {
  if [ "$VAL05_SUDOERS_INSTALLED" -eq 1 ] && [ -n "$VAL05_SUDOERS_DROPIN" ]; then
    sudo -n /bin/rm -f "$VAL05_SUDOERS_DROPIN" 2>/dev/null || true
    VAL05_SUDOERS_INSTALLED=0
  fi
}

branch_scan_base() {
  local base_ref="${GITHUB_BASE_REF:-main}"
  git merge-base "origin/$base_ref" HEAD 2>/dev/null \
    || git merge-base "$base_ref" HEAD 2>/dev/null \
    || git merge-base origin/main HEAD 2>/dev/null \
    || git merge-base main HEAD 2>/dev/null \
    || git merge-base --fork-point '@{upstream}' HEAD 2>/dev/null
}

validation_diff_base() {
  branch_scan_base 2>/dev/null || git rev-parse HEAD
}

changed_since_base() {
  local base="$1"
  { git diff --name-only "$base...HEAD" 2>/dev/null || true
    git diff --name-only 2>/dev/null || true
    git diff --cached --name-only 2>/dev/null || true
    git ls-files --others --exclude-standard 2>/dev/null || true
  } | sort -u
}

detect_validation_changes() {
  local base="$1"
  CODE_CHANGED=0
  LOCKFILE_CHANGED=0

  while IFS= read -r path; do
    [ -n "$path" ] || continue
    case "$path" in
      *.rs|*/Cargo.toml|Cargo.toml|*/Cargo.lock|Cargo.lock|rust-toolchain.toml|crates/guard-e2e/fixtures/*|crates/guard-e2e/harness/*|crates/guard-core/data/*|scripts/*.sh|tools/*)
        CODE_CHANGED=1
        ;;
    esac
    case "$path" in
      */Cargo.toml|Cargo.toml|*/Cargo.lock|Cargo.lock|rust-toolchain.toml)
        LOCKFILE_CHANGED=1
        ;;
    esac
  done < <(changed_since_base "$base")
}

# ── 0. Detect workflow-equivalent changed-file context ─────────────────────
DIFF_BASE="$(validation_diff_base)"
detect_validation_changes "$DIFF_BASE"

REPO_META_ONLY=0
if changes_only_repo_meta all; then
  REPO_META_ONLY=1
fi

if [ "$RUN_PRIVILEGED" -eq 1 ] \
  && [ "$QUICK" -ne 1 ] \
  && [ "${CI_LOCAL_SKIP_E2E:-0}" -ne 1 ] \
  && [ "$CODE_CHANGED" -eq 1 ]; then
  install_val05_sudoers
fi

# ── lint-markdown job (ubuntu) ─────────────────────────────────────────────
step "Markdown lint"
node_bin="$(command -v node || true)"
if [ -x /opt/homebrew/bin/node ]; then
  node_bin=/opt/homebrew/bin/node
fi
if [ -n "$node_bin" ]; then
  fp=$(all_md_fingerprint)
  if cache_enabled && cache_hit "ci-local:mdlint" "$fp"; then
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
if [ "$CODE_CHANGED" -ne 1 ]; then
  skip "cargo-machete (repo-meta-only change)"
else
  step "Unused dependency lint"
  fp=$(rust_fingerprint)
  if cache_enabled && cache_hit "ci-local:machete" "$fp"; then
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
    event_file="$(mktemp_tracked)"
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
if [ "$QUICK" -eq 1 ] || [ "${CI_LOCAL_SKIP_E2E:-0}" -eq 1 ] || [ "$CODE_CHANGED" -ne 1 ]; then
  if [ "$CODE_CHANGED" -ne 1 ]; then
    warn "skipping code-validation build/tests (repo-meta-only change)"
  else
    warn "skipping code-validation build/tests (--quick or CI_LOCAL_SKIP_E2E=1)"
  fi
else
  fp=$(e2e_fingerprint)

  step "code-validation lint: test env var hygiene"
  scripts/lint-test-env-vars.sh || fail "lint test env var hygiene"
  pass "lint test env var hygiene"

  step "code-validation build: cargo build --workspace --release"
  if cache_enabled && cache_hit "ci-local:cargo-build" "$fp"; then
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

  if cache_enabled && cache_hit "ci-local:e2e-all" "$fp"; then
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
  # non-interactive sudo. GitHub runs it on an ephemeral macOS runner; local
  # parity runs it by default and offers --no-privileged as the explicit opt-out.
  if [ "$RUN_PRIVILEGED" -eq 1 ]; then
    step "code-validation e2e: VAL-05 privileged init and install health"
    STT_GUARD_E2E_PRIVILEGED_INSTALL=1 \
      cargo test -p guard-e2e --test hardened_install_health --release -- --nocapture \
      || fail "VAL-05 privileged init and install health"
    pass "VAL-05 privileged init and install health"
  else
    warn "skipping code-validation e2e: VAL-05 privileged install health (--no-privileged)"
  fi
fi

step "code-validation secret scan"
if ! command -v trufflehog >/dev/null; then
  fail "trufflehog not found; install it locally (for example: brew install trufflehog)"
fi
if [ -n "$(git rev-list --max-count=1 "$DIFF_BASE..HEAD" 2>/dev/null || true)" ]; then
  trufflehog git "file://$REPO_ROOT" \
    --since-commit "$DIFF_BASE" \
    --branch HEAD \
    --results=verified \
    --fail \
    --no-update \
    || fail "secret scan failed for commits added on this branch"
fi
worktree_patch="$(mktemp_tracked)"
{ git diff --binary; git diff --cached --binary; } > "$worktree_patch"
if [ -s "$worktree_patch" ]; then
  trufflehog filesystem "$worktree_patch" \
    --results=verified \
    --fail \
    --no-update \
    || fail "secret scan failed for working tree changes"
fi
while IFS= read -r -d '' path; do
  trufflehog filesystem "$path" \
    --results=verified \
    --fail \
    --no-update \
    || fail "secret scan failed for untracked path $path"
done < <(git ls-files --others --exclude-standard -z)
pass "secret scan"

if [ "$QUICK" -eq 1 ]; then
  warn "skipping dependency CVE audit (--quick)"
elif [ "$LOCKFILE_CHANGED" -eq 1 ] || [ "${CI_LOCAL_AUDIT_ALWAYS:-0}" -eq 1 ]; then
  step "code-validation dependency CVE audit"
  if ! command -v cargo-audit >/dev/null; then
    fail "cargo-audit not found; install it locally (for example: cargo install cargo-audit)"
  fi
  cargo audit || fail "dependency CVE audit"
  pass "dependency CVE audit"
else
  skip "dependency CVE audit (no lockfile/toolchain changes; set CI_LOCAL_AUDIT_ALWAYS=1 to force)"
fi

echo -e "\n${GREEN}${BOLD}Code validation passed locally.${RESET}"
