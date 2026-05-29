#!/usr/bin/env sh
set -eu

repo="stentorian-io/guard"
version="${STT_GUARD_VERSION:-}"
yes=0

usage() {
  cat <<'EOF'
Usage: install.sh [--version vX.Y.Z] [--yes]

Downloads a verified Stentorian Guard release artifact and runs the hardened
init flow. The script runs unprivileged until it invokes sudo for init.
EOF
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --version)
      shift
      if [ "$#" -eq 0 ]; then
        echo "install.sh: --version requires a value" >&2
        exit 64
      fi
      version="$1"
      ;;
    --yes|-y)
      yes=1
      ;;
    --help|-h)
      usage
      exit 0
      ;;
    *)
      echo "install.sh: unknown argument: $1" >&2
      usage >&2
      exit 64
      ;;
  esac
  shift
done

need() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "install.sh: required command not found: $1" >&2
    exit 69
  fi
}

need curl
need tar
need shasum
need sed
need uname

os="$(uname -s)"
arch="$(uname -m)"

if [ "$os" != "Darwin" ]; then
  echo "install.sh: hardened install is currently supported on macOS only" >&2
  exit 69
fi

case "$arch" in
  arm64) target="aarch64-apple-darwin" ;;
  x86_64) target="x86_64-apple-darwin" ;;
  *)
    echo "install.sh: unsupported macOS architecture: $arch" >&2
    exit 69
    ;;
esac

if [ -z "$version" ]; then
  latest_json="$(curl -fsSL "https://api.github.com/repos/${repo}/releases/latest")"
  version="$(printf '%s\n' "$latest_json" | sed -n 's/.*"tag_name"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' | head -n 1)"
fi

if [ -z "$version" ]; then
  echo "install.sh: could not determine latest release version" >&2
  exit 69
fi

case "$version" in
  v*) tag="$version" ;;
  *) tag="v${version}" ;;
esac

version_no_v="${tag#v}"
asset="guard-${version_no_v}-${target}.tar.gz"
base_url="https://github.com/${repo}/releases/download/${tag}"

tmpdir="$(mktemp -d "${TMPDIR:-/tmp}/stt-guard-install.XXXXXX")"
cleanup() {
  rm -rf "$tmpdir"
}
trap cleanup EXIT INT TERM

echo "stt-guard: downloading ${asset}"
curl -fsSL -o "${tmpdir}/${asset}" "${base_url}/${asset}"
curl -fsSL -o "${tmpdir}/checksums.txt" "${base_url}/checksums.txt"

expected_sha="$(grep "  ${asset}$" "${tmpdir}/checksums.txt" | awk '{print $1}' | head -n 1)"
if [ -z "$expected_sha" ]; then
  echo "install.sh: no checksum found for ${asset}" >&2
  exit 65
fi

actual_sha="$(shasum -a 256 "${tmpdir}/${asset}" | awk '{print $1}')"
if [ "$actual_sha" != "$expected_sha" ]; then
  echo "install.sh: checksum mismatch for ${asset}" >&2
  echo "  expected: ${expected_sha}" >&2
  echo "  actual:   ${actual_sha}" >&2
  exit 65
fi

tar -xzf "${tmpdir}/${asset}" -C "$tmpdir"

if [ "$yes" -eq 1 ]; then
  sudo "${tmpdir}/stt-guard" init --yes
else
  sudo "${tmpdir}/stt-guard" init
fi

echo "stt-guard: installed ${tag}"
