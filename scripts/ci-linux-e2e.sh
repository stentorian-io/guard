#!/usr/bin/env bash
#
# Linux E2E parity for local hooks. Runs the LD_PRELOAD smoke suite in a Linux
# container so macOS developers verify the supported Linux runtime path before
# pushing.
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
  echo "ci-linux-e2e: $1" >&2
  exit 1
}

command -v docker >/dev/null || fail "docker is required for Linux E2E parity"
docker info >/dev/null 2>&1 || fail "docker is not running"
mkdir -p "$CARGO_REGISTRY_CACHE" "$RUSTUP_CACHE" "$TARGET_CACHE"

docker run --rm \
  -v "$REPO_ROOT:/work" \
  -v "$CARGO_REGISTRY_CACHE:/usr/local/cargo/registry" \
  -v "$RUSTUP_CACHE:/usr/local/rustup" \
  -v "$TARGET_CACHE:/target" \
  -w /work \
  "$IMAGE" \
  bash -lc 'set -euo pipefail; export PATH=/usr/local/cargo/bin:$PATH; export CARGO_TARGET_DIR=/target; cargo build -p guard-cli --release; cargo test -p guard-e2e --test linux_system_install_gate --release -- --nocapture; cargo test -p guard-hook --test linux_ld_preload_smoke -- --nocapture'
