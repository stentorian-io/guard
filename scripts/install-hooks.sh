#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
HOOKS_DIR="$REPO_ROOT/.git/hooks"

install_hook() {
  local name="$1"
  local src="$REPO_ROOT/scripts/$name"
  local dst="$HOOKS_DIR/$name"

  if [ ! -f "$src" ]; then
    echo "error: scripts/$name not found" >&2
    exit 1
  fi

  cp "$src" "$dst"
  chmod +x "$dst"
  echo "$name hook installed → .git/hooks/$name"
}

install_hook pre-commit
install_hook commit-msg
