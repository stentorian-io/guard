#!/usr/bin/env sh
set -eu

purge=0
yes=0

usage() {
  cat <<'EOF'
Usage: uninstall.sh [--purge] [--yes]

Removes the Stentorian Guard LaunchDaemon and root-owned binaries.
By default, daemon state, user rules, and logs are preserved.

Options:
  --purge   Also remove daemon state and logs.
  --yes     Skip the confirmation prompt.
EOF
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --purge)
      purge=1
      ;;
    --yes|-y)
      yes=1
      ;;
    --help|-h)
      usage
      exit 0
      ;;
    *)
      echo "uninstall.sh: unknown argument: $1" >&2
      usage >&2
      exit 64
      ;;
  esac
  shift
done

if [ "$(uname -s)" != "Darwin" ]; then
  echo "uninstall.sh: hardened uninstall is currently supported on macOS only" >&2
  exit 69
fi

if [ "$yes" -ne 1 ]; then
  if [ "$purge" -eq 1 ]; then
    prompt="Remove Stentorian Guard binaries, LaunchDaemon, state, rules, and logs? [y/N] "
  else
    prompt="Remove Stentorian Guard binaries and LaunchDaemon, preserving state and logs? [y/N] "
  fi
  printf '%s' "$prompt"
  read -r answer
  case "$answer" in
    y|Y|yes|YES) ;;
    *)
      echo "uninstall.sh: aborted"
      exit 0
      ;;
  esac
fi

plist="/Library/LaunchDaemons/io.stentorian.guard.daemon.plist"
bin_dir="/usr/local/libexec/stt-guard"
state_dir="/Library/Application Support/Stentorian Guard"
log_dir="/var/log/stt-guard"

sudo launchctl bootout system/io.stentorian.guard.daemon >/dev/null 2>&1 || true
sudo rm -f "$plist"
sudo rm -rf "$bin_dir"

if [ "$purge" -eq 1 ]; then
  sudo rm -rf "$state_dir"
  sudo rm -rf "$log_dir"
  echo "stt-guard: uninstalled and purged state"
else
  echo "stt-guard: uninstalled; state and logs preserved"
  echo "stt-guard: rerun with --purge to remove ${state_dir} and ${log_dir}"
fi
