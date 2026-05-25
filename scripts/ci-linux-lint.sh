#!/usr/bin/env bash
#
# Linux lint parity for local hooks. Mirrors the GitHub Actions lint job's
# Rust checks on a Linux runner so macOS developers catch target-specific
# all-target Clippy failures before pushing.
#
set -euo pipefail

REPO_ROOT="$(git rev-parse --show-toplevel)"
cd "$REPO_ROOT"

IMAGE="rust:1.95.0-bookworm"
CACHE_ROOT="/private/tmp/stt-guard-docker"
CARGO_REGISTRY_CACHE="$CACHE_ROOT/cargo-registry"
RUSTUP_CACHE="$CACHE_ROOT/rustup"
TARGET_CACHE="$CACHE_ROOT/target"

fail() {
  echo "ci-linux-lint: $1" >&2
  exit 1
}

command -v docker >/dev/null || fail "docker is required for Linux CI lint parity"
docker info >/dev/null 2>&1 || fail "docker is not running"
mkdir -p "$CARGO_REGISTRY_CACHE" "$RUSTUP_CACHE" "$TARGET_CACHE"

docker run --rm \
  -v "$REPO_ROOT:/work" \
  -v "$CARGO_REGISTRY_CACHE:/usr/local/cargo/registry" \
  -v "$RUSTUP_CACHE:/usr/local/rustup" \
  -v "$TARGET_CACHE:/target" \
  -w /work \
  "$IMAGE" \
  bash -lc 'set -euo pipefail; export PATH=/usr/local/cargo/bin:$PATH; export CARGO_TARGET_DIR=/target; cargo fmt --check; cargo clippy --workspace --all-targets -- -D warnings'
