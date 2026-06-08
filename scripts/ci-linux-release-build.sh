#!/usr/bin/env bash
#
# Linux release build parity for local hooks. Runs the Linux release build in
# the same Rust container family used by CI so macOS developers catch Linux
# release artifact failures before committing.
#
set -euo pipefail

REPO_ROOT="$(git rev-parse --show-toplevel)"
cd "$REPO_ROOT"

IMAGE="rust:1.96.0-bookworm"
CACHE_ROOT="/private/tmp/stt-guard-docker"
CARGO_REGISTRY_CACHE="$CACHE_ROOT/cargo-registry"
RUSTUP_CACHE="$CACHE_ROOT/rustup"
TARGET_CACHE="$CACHE_ROOT/target"

fail() {
  echo "ci-linux-release-build: $1" >&2
  exit 1
}

command -v docker >/dev/null || fail "docker is required for Linux release build parity"
docker info >/dev/null 2>&1 || fail "docker is not running"
mkdir -p "$CARGO_REGISTRY_CACHE" "$RUSTUP_CACHE" "$TARGET_CACHE"

docker run --rm \
  -v "$REPO_ROOT:/work" \
  -v "$CARGO_REGISTRY_CACHE:/usr/local/cargo/registry" \
  -v "$RUSTUP_CACHE:/usr/local/rustup" \
  -v "$TARGET_CACHE:/target" \
  -w /work \
  "$IMAGE" \
  bash -lc 'set -euo pipefail; export PATH=/usr/local/cargo/bin:$PATH; export CARGO_TARGET_DIR=/target; cargo build --workspace --release; cargo build -p guard-cli -p guard-daemon -p guard-hook --release --features test-signer'
