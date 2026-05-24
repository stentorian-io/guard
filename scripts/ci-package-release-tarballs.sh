#!/usr/bin/env bash
set -euo pipefail

: "${GITHUB_OUTPUT:?GITHUB_OUTPUT is required}"

version="${1:?usage: ci-package-release-tarballs.sh <version>}"

for target_dir in artifacts/guard-*; do
  target="${target_dir#artifacts/guard-}"
  cp artifacts/release-meta.json "${target_dir}/release-meta.json"
  tarball="artifacts/guard-${version}-${target}.tar.gz"
  tar -C "${target_dir}" \
    -czf "${tarball}" \
    stt-guard stt-guard-daemon stt-guard-watchdog stt-guard-hook.dylib release-meta.json
  sha=$(sha256sum "${tarball}" | awk '{print $1}')
  case "${target}" in
    aarch64-apple-darwin)
      echo "arm64_tarball=${tarball}" >> "$GITHUB_OUTPUT"
      echo "arm64_sha256=${sha}" >> "$GITHUB_OUTPUT"
      ;;
    x86_64-apple-darwin)
      echo "x86_64_tarball=${tarball}" >> "$GITHUB_OUTPUT"
      echo "x86_64_sha256=${sha}" >> "$GITHUB_OUTPUT"
      ;;
    *)
      echo "unexpected target: ${target}" >&2
      exit 1
      ;;
  esac
done
