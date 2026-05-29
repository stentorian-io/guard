#!/usr/bin/env bash
#
# Run macOS E2E validation inside a disposable Tart macOS VM so the host system
# install is not mutated. This script fails if hardened_install_health reports
# an internal SKIP, because the local no-skip target must prove privileged
# install health instead of silently accepting a missing test capability.
#
# Requirements:
#   brew install cirruslabs/cli/tart hudochenkov/sshpass/sshpass
#   tart clone ghcr.io/cirruslabs/macos-tahoe-base:latest stt-guard-macos-base
#
# The guest image must be CI-ready enough to build this workspace: Xcode
# command-line tools plus network access for Rust/Node bootstrap. The default
# Cirrus macOS base images use admin/admin credentials.

set -euo pipefail

REPO_ROOT="$(git rev-parse --show-toplevel)"
cd "$REPO_ROOT"

BASE_IMAGE="${STT_GUARD_MACOS_VM_BASE:-ghcr.io/cirruslabs/macos-tahoe-base:latest}"
BASE_NAME="${STT_GUARD_MACOS_VM_BASE_NAME:-stt-guard-macos-base}"
VM_NAME="${STT_GUARD_MACOS_VM_NAME:-stt-guard-e2e-$(date +%Y%m%d%H%M%S)-$$}"
VM_USER="${STT_GUARD_MACOS_VM_USER:-admin}"
VM_PASSWORD="${STT_GUARD_MACOS_VM_PASSWORD:-admin}"
REMOTE_ROOT="${STT_GUARD_MACOS_VM_REMOTE_ROOT:-/Users/$VM_USER/stt-guard}"
SSH_OPTS=(
  -o StrictHostKeyChecking=no
  -o UserKnownHostsFile=/dev/null
  -o PubkeyAuthentication=no
  -o PreferredAuthentications=password
  -o NumberOfPasswordPrompts=1
  -o ConnectTimeout=10
  -o ServerAliveInterval=15
)

fail() {
  echo "ci-macos-vm-e2e: $1" >&2
  exit 1
}

need_cmd() {
  command -v "$1" >/dev/null || fail "$1 is required"
}

need_cmd tart
need_cmd sshpass
need_cmd rsync

vm_exists() {
  tart list 2>/dev/null | awk 'NR > 1 {print $2}' | grep -Fxq "$1"
}

ensure_base_image() {
  if vm_exists "$BASE_NAME"; then
    return
  fi

  echo "ci-macos-vm-e2e: cloning base image $BASE_IMAGE -> $BASE_NAME"
  tart clone "$BASE_IMAGE" "$BASE_NAME"
}

ssh_guest() {
  local ip="$1"
  shift
  sshpass -p "$VM_PASSWORD" ssh "${SSH_OPTS[@]}" "$VM_USER@$ip" "$@"
}

rsync_to_guest() {
  local ip="$1"
  rsync -az --delete \
    -e "sshpass -p '$VM_PASSWORD' ssh ${SSH_OPTS[*]}" \
    --exclude .git \
    --exclude target \
    --exclude .gsd \
    "$REPO_ROOT/" \
    "$VM_USER@$ip:$REMOTE_ROOT/"
}

cleanup() {
  set +e
  if vm_exists "$VM_NAME"; then
    tart stop "$VM_NAME" >/dev/null 2>&1
    tart delete "$VM_NAME" >/dev/null 2>&1
  fi
}
trap cleanup EXIT

wait_for_ip() {
  local deadline=$((SECONDS + 180))
  local ip=""
  while [ "$SECONDS" -lt "$deadline" ]; do
    ip="$(tart ip "$VM_NAME" 2>/dev/null || true)"
    if [ -n "$ip" ]; then
      printf '%s\n' "$ip"
      return
    fi
    sleep 3
  done

  fail "timed out waiting for VM IP"
}

wait_for_ssh() {
  local ip="$1"
  local deadline=$((SECONDS + 180))
  while [ "$SECONDS" -lt "$deadline" ]; do
    if ssh_guest "$ip" "true" >/dev/null 2>&1; then
      return
    fi
    sleep 3
  done

  fail "timed out waiting for SSH on $ip"
}

configure_guest() {
  local ip="$1"
  ssh_guest "$ip" "cat > /tmp/stt-guard-guest-setup.sh && bash /tmp/stt-guard-guest-setup.sh" <<'GUEST_SETUP'
set -euo pipefail

echo "$USER ALL=(ALL) NOPASSWD: ALL" | sudo -S tee /etc/sudoers.d/stt-guard-ci-nopasswd >/dev/null
sudo chmod 440 /etc/sudoers.d/stt-guard-ci-nopasswd
sudo -n true

if ! command -v cargo >/dev/null; then
  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal
fi

if [ -f "$HOME/.cargo/env" ]; then
  # shellcheck disable=SC1091
  . "$HOME/.cargo/env"
fi

if ! command -v node >/dev/null; then
  if command -v brew >/dev/null; then
    brew install node@20
    brew link --force node@20 || true
    export PATH="/opt/homebrew/opt/node@20/bin:/usr/local/opt/node@20/bin:$PATH"
  else
    export NVM_DIR="$HOME/.nvm"
    curl -fsSL https://raw.githubusercontent.com/nvm-sh/nvm/v0.40.3/install.sh | bash
    # shellcheck disable=SC1091
    . "$NVM_DIR/nvm.sh"
    nvm install 20
    nvm alias default 20
  fi
fi

if [ -s "$HOME/.nvm/nvm.sh" ]; then
  export NVM_DIR="$HOME/.nvm"
  # shellcheck disable=SC1091
  . "$NVM_DIR/nvm.sh"
fi

rustc --version
cargo --version
node --version
GUEST_SETUP
}

run_guest_e2e() {
  local ip="$1"
  ssh_guest "$ip" "cd '$REMOTE_ROOT' && cat > /tmp/stt-guard-run-e2e.sh && bash /tmp/stt-guard-run-e2e.sh" <<'GUEST_RUN'
set -euo pipefail

if [ -f "$HOME/.cargo/env" ]; then
  # shellcheck disable=SC1091
  . "$HOME/.cargo/env"
fi

export PATH="$HOME/.cargo/bin:/opt/homebrew/bin:/usr/local/bin:$PATH"
export PATH="/opt/homebrew/opt/node@20/bin:/usr/local/opt/node@20/bin:$PATH"
if [ -s "$HOME/.nvm/nvm.sh" ]; then
  export NVM_DIR="$HOME/.nvm"
  # shellcheck disable=SC1091
  . "$NVM_DIR/nvm.sh"
fi
export STT_GUARD_E2E_PRIVILEGED_INSTALL=1

cargo build --workspace --release
cargo build -p guard-cli -p guard-daemon -p guard-hook --release --features test-signer
cargo test -p guard-e2e --features test-signer --test ua_parser_js_demo --release -- --nocapture
cargo test -p guard-e2e --features test-signer --test workers_dev_validation --release -- --nocapture
cargo test -p guard-e2e --features test-signer --test failure_modes_corrupt_snapshot --release -- --nocapture
cargo test -p guard-e2e --features test-signer --test failure_modes_hardened_exec --release -- --nocapture
cargo test -p guard-e2e --features test-signer --test hardened_install_health --release -- --nocapture 2>&1 | tee /tmp/stt-guard-hardened-install-health.log
if grep -q '^SKIP:' /tmp/stt-guard-hardened-install-health.log; then
  echo "hardened_install_health reported SKIP; this VM cannot provide no-skip privileged validation" >&2
  exit 2
fi
GUEST_RUN
}

ensure_base_image

echo "ci-macos-vm-e2e: cloning disposable VM $BASE_NAME -> $VM_NAME"
tart clone "$BASE_NAME" "$VM_NAME"

echo "ci-macos-vm-e2e: starting $VM_NAME"
tart run --no-graphics "$VM_NAME" >/tmp/"$VM_NAME".log 2>&1 &

ip="$(wait_for_ip)"
echo "ci-macos-vm-e2e: VM IP is $ip"
wait_for_ssh "$ip"
configure_guest "$ip"

echo "ci-macos-vm-e2e: syncing repository to guest"
rsync_to_guest "$ip"

echo "ci-macos-vm-e2e: running macOS E2E suite with privileged install health"
run_guest_e2e "$ip"

echo "ci-macos-vm-e2e: complete"
