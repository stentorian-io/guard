#!/bin/bash
# fixtures/vendor-ua-parser-js.sh - deterministic builder for the synthetic
# ua-parser-js@0.7.29 fixture used by Stentorian Guard's VAL-01 e2e validation.
#
# *** SYNTHETIC MOCK ***
#
# This script does NOT vendor any real malicious bytes. It constructs a
# hand-rolled mock that reproduces the SHAPE of the historical 2021
# ua-parser-js@0.7.29 supply-chain attack - a postinstall script that opens
# an outbound TCP connection - without containing any real malware, miner
# payload, exfil keylogger, or live C2 hostname.
#
# Why synthetic instead of a real-tarball reconstruction?
#   The original Plan 05-01 specified reconstruction from public github
#   commits 90fb09d8 / 8742775c / e09c01ed. Those commits were SCRUBBED
#   from github.com/faisalman/ua-parser-js in early 2026 (404 on github,
#   no Wayback snapshot). CONTEXT D-06 explicitly named "synthetic mock"
#   as the legitimate v0.2+ alternative if upstream fidelity becomes
#   unattainable. Per the orchestrator-confirmed Rule 4 architectural
#   pivot recorded in Plan 05-01 SUMMARY, that escape hatch is now
#   invoked.
#
# What this script DOES (deterministic, byte-identical across hosts):
#   1. Construct an in-tempdir `package/` tree:
#      - package.json (synthetic, declares preinstall script)
#      - preinstall.js (opens TCP to c2-sink.test.invalid:443, then exits 0)
#      - index.js (empty stub so `require('ua-parser-js')` does not throw)
#   2. Pack the tree into a .tgz with normalized owner/group/mtime so the
#      output is byte-identical regardless of build host.
#   3. Compute shasum -a 256 of the output and verify it matches the
#      EXPECTED_OUTPUT_SHA256 pin embedded in this script.
#   4. Copy the verified .tgz into the fixture directory.
#
# Pin bootstrap workflow:
#   First run:               bash fixtures/vendor-ua-parser-js.sh
#                            (script prints actual hash, refuses to write
#                             fixture; pin is still <FILL_ON_FIRST_RUN>)
#   Embed the pin:           bash fixtures/vendor-ua-parser-js.sh --update-pin
#                            (script accepts the freshly-computed hash and
#                             rewrites EXPECTED_OUTPUT_SHA256 in place)
#   Verify clean re-run:     bash fixtures/vendor-ua-parser-js.sh
#                            (exit 0; fixture written; subsequent runs are
#                             tamper-detection)
#
# CI never runs this script. CI verifies the COMMITTED tarball against the
# pinned EXPECTED_OUTPUT_SHA256 (per CONTEXT D-02 / D-15).
#
# macOS BSD shell tooling:
#   - shasum -a 256       (NOT sha256sum - Apple ships shasum)
#   - sed -i ''           (BSD sed: empty string after -i is REQUIRED in-place; GNU sed differs)
#   - tar (libarchive)    (BSD/libarchive bsdtar 3.x - accepts --uid/--gid/--uname/--gname
#                          for normalized ownership; mtime determinism via touch + gzip -n)
#
# Zip-slip safety note: this script does not extract any input tarball
# (synthetic mocks have no upstream source). The `--no-same-owner` and
# `--no-same-permissions` extraction guards from the original
# reconstruction recipe are therefore not present. If a future revision
# re-introduces an extraction step, those flags MUST be re-added - see
# the fixture reconstruction security notes.
#
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "$script_dir/.." && pwd)"
fixture_dir="$repo_root/crates/guard-e2e/fixtures/ua-parser-js-0.7.29-sanitized"
tempdir="$(mktemp -d)"
trap 'rm -rf "$tempdir"' EXIT

EXPECTED_OUTPUT_SHA256="70f5af6cde74fdb75c698c3045de459e277ae1bdd4324d28be89328e258b2f07"

SINK_HOST="c2-sink.test.invalid"
SINK_PORT="443"

update_pin=0
if [ "${1:-}" = "--update-pin" ]; then
    update_pin=1
fi

echo ">>> Step 1: write synthetic package/ tree"
build_dir="$tempdir/build"
pkg_dir="$build_dir/package"
mkdir -p "$pkg_dir"

cat > "$pkg_dir/package.json" <<'JSON'
{
  "name": "ua-parser-js",
  "version": "0.7.29",
  "description": "Synthetic mock of ua-parser-js@0.7.29 for Stentorian Guard VAL-01 e2e validation. Reproduces the postinstall->network-egress supply-chain attack shape; contains no real malicious bytes.",
  "scripts": {
    "preinstall": "node preinstall.js"
  },
  "main": "index.js"
}
JSON

cat > "$pkg_dir/preinstall.js" <<JS
// Synthetic supply-chain attack shape — reproduces postinstall->network-egress
// without containing any real malicious bytes. Stentorian Guard VAL-01 asserts that
// the connection attempt below is intercepted and denied.
'use strict';
var net = require('net');
process.stdout.write('ua-parser-js-mock: attempting connect to ${SINK_HOST}:${SINK_PORT}\n');
var sock = net.createConnection({ host: '${SINK_HOST}', port: ${SINK_PORT} });
var done = false;
function finish() {
  if (done) return;
  done = true;
  try { sock.destroy(); } catch (_) {}
  process.exit(0);
}
sock.on('error', finish);   // Stentorian Guard may EHOSTUNREACH us.
sock.on('connect', finish); // A leak should not hang npm forever.
setTimeout(finish, 1000);
JS

cat > "$pkg_dir/index.js" <<'JS'
'use strict';
module.exports = {};
JS

echo "    package/package.json:  $(wc -c < "$pkg_dir/package.json" | tr -d ' ') bytes"
echo "    package/preinstall.js: $(wc -c < "$pkg_dir/preinstall.js" | tr -d ' ') bytes"
echo "    package/index.js:      $(wc -c < "$pkg_dir/index.js" | tr -d ' ') bytes"

echo ">>> Step 2: pack -> deterministic .tgz"
out_tgz="$tempdir/ua-parser-js-0.7.29-sanitized.tgz"

touch -t 202001010000.00 \
    "$pkg_dir/package.json" "$pkg_dir/preinstall.js" "$pkg_dir/index.js"

uncompressed_tar="$tempdir/sanitized.tar"
(
    cd "$build_dir"
    find package -type f -print | LC_ALL=C sort | \
        /usr/bin/tar -cf "$uncompressed_tar" \
            --uid 0 --gid 0 --uname '' --gname '' \
            -T -
)

gzip -n -9 < "$uncompressed_tar" > "$out_tgz"

actual_output=$(shasum -a 256 "$out_tgz" | awk '{print $1}')
echo "    output SHA-256: $actual_output"

if [ "$update_pin" = "1" ]; then
    sed -i '' \
        "s|^EXPECTED_OUTPUT_SHA256=\".*\"|EXPECTED_OUTPUT_SHA256=\"$actual_output\"|" \
        "$script_dir/vendor-ua-parser-js.sh"
    echo ""
    echo "EXPECTED_OUTPUT_SHA256 pin updated in-place to:"
    echo "  $actual_output"
    echo ""
    echo "Re-run \`bash fixtures/vendor-ua-parser-js.sh\` (without --update-pin) to verify."
    exit 0
fi

if [ "$EXPECTED_OUTPUT_SHA256" = "<FILL_ON_FIRST_RUN>" ]; then
    echo ""
    echo "Pin not yet set. Re-run with --update-pin to embed the hash above:"
    echo "  bash fixtures/vendor-ua-parser-js.sh --update-pin"
    exit 1
fi

if [ "$actual_output" != "$EXPECTED_OUTPUT_SHA256" ]; then
    echo "FATAL: output tarball hash mismatch"
    echo "  expected: $EXPECTED_OUTPUT_SHA256"
    echo "  actual:   $actual_output"
    exit 1
fi

mkdir -p "$fixture_dir"
cp "$out_tgz" "$fixture_dir/ua-parser-js-0.7.29-sanitized.tgz"

echo ""
echo "Done. Committed-output path: $fixture_dir/ua-parser-js-0.7.29-sanitized.tgz"
echo "  output SHA-256: $actual_output"
