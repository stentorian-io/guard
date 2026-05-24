#!/usr/bin/env bash
set -euo pipefail

fixture=crates/guard-e2e/fixtures/ua-parser-js-0.7.29-sanitized/ua-parser-js-0.7.29-sanitized.tgz
test -f "$fixture" || { echo "FATAL: sanitized fixture missing"; exit 1; }

if command -v sha256sum >/dev/null; then
  actual=$(sha256sum "$fixture" | awk '{print $1}')
else
  actual=$(shasum -a 256 "$fixture" | awk '{print $1}')
fi
echo "Fixture SHA-256: $actual"

matches=$(grep -c '^EXPECTED_OUTPUT_SHA256="[a-f0-9]\{64\}"$' \
  tools/vendor-ua-parser-js.sh || true)
if [ "$matches" -ne 1 ]; then
  echo "FATAL: expected exactly one EXPECTED_OUTPUT_SHA256=\"<64-hex>\" line in tools/vendor-ua-parser-js.sh, found $matches"
  exit 1
fi

pinned=$(grep '^EXPECTED_OUTPUT_SHA256="[a-f0-9]\{64\}"$' \
  tools/vendor-ua-parser-js.sh \
  | sed -E 's/^EXPECTED_OUTPUT_SHA256="([a-f0-9]{64})"$/\1/')
if [ -z "$pinned" ] || [ "$pinned" = "<FILL_ON_FIRST_RUN>" ]; then
  echo "FATAL: tools/vendor-ua-parser-js.sh has no committed pinned hash"
  exit 1
fi
if [ "$actual" != "$pinned" ]; then
  echo "FATAL: fixture hash mismatch — fixture drifted from script pin"
  echo "  script pin: $pinned"
  echo "  on-disk:    $actual"
  exit 1
fi

echo "Fixture hash matches script pin."
