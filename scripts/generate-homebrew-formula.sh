#!/usr/bin/env bash
# Generate the Homebrew formula for a tagged Stentorian Guard release.
# Usage:
#   scripts/generate-homebrew-formula.sh \
#     <version> <arm64-url> <arm64-sha256> <x86_64-url> <x86_64-sha256>
set -euo pipefail

VERSION="${1:?usage: generate-homebrew-formula.sh <version> <arm64-url> <arm64-sha256> <x86_64-url> <x86_64-sha256>}"
ARM64_URL="${2:?missing arm64 URL}"
ARM64_SHA="${3:?missing arm64 sha256}"
X86_64_URL="${4:?missing x86_64 URL}"
X86_64_SHA="${5:?missing x86_64 sha256}"

cat <<EOF
# typed: false
# frozen_string_literal: true

class SttGuard < Formula
  desc "Default-deny outbound network guard for developer commands"
  homepage "https://github.com/stentorian-io/guard"
  version "${VERSION}"
  license any_of: ["MIT", "Apache-2.0"]

  on_macos do
    on_arm do
      url "${ARM64_URL}"
      sha256 "${ARM64_SHA}"
    end

    on_intel do
      url "${X86_64_URL}"
      sha256 "${X86_64_SHA}"
    end
  end

  def install
    libexec.install "stt-guard"
    libexec.install "stt-guard-daemon"
    libexec.install "stt-guard-watchdog"
    libexec.install "stt-guard-hook.dylib"
    libexec.install "release-meta.json"

    bin.write_exec_script libexec/"stt-guard"
  end

  def caveats
    <<~EOS
      Finish the hardened system setup with:

        sudo stt-guard init

      stt-guard wrap/status intentionally refuse to run until init verifies the
      root-owned deployment layout. Manual binary installation is unsupported.
    EOS
  end

  test do
    assert_match version.to_s, shell_output("#{bin}/stt-guard --version")
  end
end
EOF
