#!/bin/bash
# tools/vendor-ua-parser-js.sh — one-shot reconstruction of a sanitized
# ua-parser-js@0.7.29 tarball. Run by maintainers, NOT by CI. Output is
# committed to crates/sentinel-e2e/fixtures/ua-parser-js-0.7.29-sanitized/.
#
# Reconstruction recipe per CONTEXT C-02:
#   1. Pull ua-parser-js@0.7.28 from npm via `npm pack` (still published; pinned SHA-256).
#   2. Extract tarball into a tempdir with --no-same-owner --no-same-permissions.
#   3. Add preinstall.{js,sh,bat} from github commits 90fb09d8 / 8742775c / e09c01ed.
#   4. Bump `version` to "0.7.29" in package.json.
#   5. Apply the C-03 darwin-platform patch (rewrite the platform string check
#      so the malicious dispatch fires on macOS).
#   6. sed-rewrite ALL known C2 hostnames/IPs to `c2-sink.test.invalid`.
#   7. `npm pack` to produce the sanitized tarball.
#   8. Verify output `shasum -a 256` matches EXPECTED_OUTPUT_SHA256 pin.
#
# CI never runs this script. CI verifies the COMMITTED tarball against the
# pinned EXPECTED_OUTPUT_SHA256 (per CONTEXT D-02 / D-15).
#
# macOS BSD shell tooling (RESEARCH §Environment Availability):
#   - shasum -a 256       (NOT sha256sum — Apple ships shasum)
#   - sed -i ''           (BSD sed: empty string after -i is REQUIRED in-place; GNU sed differs)
#   - tar -xzf            (BSD tar; --no-same-owner --no-same-permissions are accepted)
#   - npm pack            (npm 10.x; required for repacking)
#   - git                 (required for `git show <SHA>:<file>` of the malicious commits)
set -euo pipefail

# Paths.
script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "$script_dir/.." && pwd)"
fixture_dir="$repo_root/crates/sentinel-e2e/fixtures/ua-parser-js-0.7.29-sanitized"
tempdir="$(mktemp -d)"
trap 'rm -rf "$tempdir"' EXIT

# Pinned hashes — fill in on first successful run, then commit alongside the tarball.
# Replace the literal "<FILL_ON_FIRST_RUN>" with real hashes after the first script
# execution; subsequent runs MUST match the pinned values byte-for-byte.
EXPECTED_SOURCE_SHA256="<FILL_ON_FIRST_RUN>"
EXPECTED_OUTPUT_SHA256="<FILL_ON_FIRST_RUN>"

# Pinned malicious commits per CONTEXT C-02.
COMMIT_PRIMARY="90fb09d8"
COMMIT_RELATED_1="8742775c"
COMMIT_RELATED_2="e09c01ed"
GITHUB_REPO="https://github.com/faisalman/ua-parser-js.git"

# Step 1: pull ua-parser-js@0.7.28 from npm.
echo ">>> Step 1: npm pack ua-parser-js@0.7.28"
(cd "$tempdir" && npm pack ua-parser-js@0.7.28 >/dev/null)
source_tgz="$tempdir/ua-parser-js-0.7.28.tgz"
[ -f "$source_tgz" ] || { echo "FATAL: npm pack did not produce expected tarball"; exit 1; }

# Verify source SHA-256 matches pin (BSD shasum, not GNU sha256sum).
actual_source=$(shasum -a 256 "$source_tgz" | awk '{print $1}')
if [ "$EXPECTED_SOURCE_SHA256" != "<FILL_ON_FIRST_RUN>" ] && [ "$actual_source" != "$EXPECTED_SOURCE_SHA256" ]; then
    echo "FATAL: source tarball hash mismatch"
    echo "  expected: $EXPECTED_SOURCE_SHA256"
    echo "  actual:   $actual_source"
    exit 1
fi
echo "    source SHA-256: $actual_source"

# Step 2: extract with safety flags (V12 zip-slip mitigation).
echo ">>> Step 2: extract tarball (--no-same-owner --no-same-permissions)"
extract_dir="$tempdir/extract"
mkdir -p "$extract_dir"
tar -xzf "$source_tgz" -C "$extract_dir" --no-same-owner --no-same-permissions
# Defense-in-depth: reject any path containing `..` post-extract.
if find "$extract_dir" -name '..' -print0 | grep -q .; then
    echo "FATAL: zip-slip detected in extracted tarball"; exit 1
fi
pkg_dir="$extract_dir/package"
[ -d "$pkg_dir" ] || { echo "FATAL: tarball did not contain package/ dir"; exit 1; }

# Step 3: fetch malicious preinstall files from github commits and copy in.
echo ">>> Step 3: fetch preinstall.{js,sh,bat} from commits $COMMIT_PRIMARY / $COMMIT_RELATED_1 / $COMMIT_RELATED_2"
git_clone="$tempdir/ua-parser-js-clone"
git clone --quiet "$GITHUB_REPO" "$git_clone"
# Try the primary commit first; fall back to related commits if a file is missing.
for file in preinstall.js preinstall.sh preinstall.bat; do
    found=""
    for sha in "$COMMIT_PRIMARY" "$COMMIT_RELATED_1" "$COMMIT_RELATED_2"; do
        if git -C "$git_clone" show "$sha:$file" > "$pkg_dir/$file" 2>/dev/null; then
            found="$sha"
            break
        fi
    done
    [ -n "$found" ] || { echo "FATAL: $file not found in any pinned commit"; exit 1; }
    echo "    $file <- commit $found"
done

# Step 4: bump version.
echo ">>> Step 4: bump version to 0.7.29 in package.json"
# BSD sed in-place requires `''` after -i.
sed -i '' 's/"version": *"0\.7\.28"/"version": "0.7.29"/' "$pkg_dir/package.json"
grep -q '"version": *"0.7.29"' "$pkg_dir/package.json" || { echo "FATAL: version bump failed"; exit 1; }

# Step 5: C-03 darwin-platform patch — make the malicious branch fire on macOS.
# preinstall.js has `if (opsys === "MacOS") return;` (or equivalent) that no-ops on darwin.
# Rewrite the platform check so darwin dispatches to the (now-sanitized) malicious branch.
echo ">>> Step 5: C-03 darwin-platform patch"
# Cover both single- and double-quoted forms; cover both `process.platform` and an
# `opsys`-style platform variable assigned from process.platform.
sed -i '' \
    "s|process.platform === 'darwin'|process.platform === '__sentinel_disabled__'|g" \
    "$pkg_dir/preinstall.js"
sed -i '' \
    's|process.platform === "darwin"|process.platform === "__sentinel_disabled__"|g' \
    "$pkg_dir/preinstall.js"
sed -i '' \
    "s|opsys == 'MacOS'|opsys == '__sentinel_disabled__'|g" \
    "$pkg_dir/preinstall.js"
sed -i '' \
    's|opsys == "MacOS"|opsys == "__sentinel_disabled__"|g' \
    "$pkg_dir/preinstall.js"
sed -i '' \
    "s|opsys === 'MacOS'|opsys === '__sentinel_disabled__'|g" \
    "$pkg_dir/preinstall.js"
sed -i '' \
    's|opsys === "MacOS"|opsys === "__sentinel_disabled__"|g' \
    "$pkg_dir/preinstall.js"
# Verify SOMETHING was patched (preinstall.js MUST contain the disabled marker now).
grep -q '__sentinel_disabled__' "$pkg_dir/preinstall.js" || \
    { echo "FATAL: C-03 darwin patch had no effect — preinstall.js platform check shape changed"; exit 1; }

# Step 6: sink-rewrite all C2 hostnames/IPs (per RESEARCH §Tertiary IoC list).
# These are the historical IoCs documented in the public CVE writeups for
# ua-parser-js@0.7.29; we rewrite each to a sink hostname that does not exist.
echo ">>> Step 6: rewrite C2 hosts to c2-sink.test.invalid"
SINK="c2-sink.test.invalid"
for c2 in \
    "159.148.186.228" \
    "citationsherbe.at" \
    "194.76.225.46" \
    "185.158.250.216" \
    "45.11.180.153" \
    "194.76.225.61" \
    "xmr-eu1.nanopool.org" \
    "sdd.bdvl"; do
    # Apply to both preinstall.js and preinstall.sh; .bat is windows-only but rewrite for completeness.
    for target in "$pkg_dir"/preinstall.js "$pkg_dir"/preinstall.sh "$pkg_dir"/preinstall.bat; do
        [ -f "$target" ] || continue
        sed -i '' "s|${c2}|${SINK}|g" "$target"
    done
done
# Verify NO original C2 string survives in the patched files (negative grep gate).
# --include='preinstall.*' scopes the grep to the rewritten files only — the script's
# own source contains the pre-rewrite literals and must not self-invalidate.
for c2 in "159.148.186.228" "citationsherbe.at" "xmr-eu1.nanopool.org"; do
    if grep -r --include='preinstall.*' -F "$c2" "$pkg_dir"; then
        echo "FATAL: C2 string '$c2' survived sanitization"; exit 1
    fi
done

# Step 7: npm pack.
echo ">>> Step 7: npm pack -> sanitized tarball"
output_dir="$tempdir/output"
mkdir -p "$output_dir"
(cd "$pkg_dir" && npm pack --pack-destination "$output_dir" >/dev/null)
sanitized_tgz="$output_dir/ua-parser-js-0.7.29.tgz"
[ -f "$sanitized_tgz" ] || { echo "FATAL: npm pack did not produce 0.7.29 tarball"; exit 1; }

# Step 8: verify output SHA-256 matches pin.
actual_output=$(shasum -a 256 "$sanitized_tgz" | awk '{print $1}')
if [ "$EXPECTED_OUTPUT_SHA256" != "<FILL_ON_FIRST_RUN>" ] && [ "$actual_output" != "$EXPECTED_OUTPUT_SHA256" ]; then
    echo "FATAL: output tarball hash mismatch"
    echo "  expected: $EXPECTED_OUTPUT_SHA256"
    echo "  actual:   $actual_output"
    exit 1
fi
echo "    output SHA-256: $actual_output"

# Copy into the fixture directory under the canonical filename.
mkdir -p "$fixture_dir"
cp "$sanitized_tgz" "$fixture_dir/ua-parser-js-0.7.29-sanitized.tgz"

echo ""
echo "Done. Committed-output path: $fixture_dir/ua-parser-js-0.7.29-sanitized.tgz"
echo "  source SHA-256: $actual_source"
echo "  output SHA-256: $actual_output"
echo ""
echo "If this is the first run, paste those two hashes into:"
echo "  EXPECTED_SOURCE_SHA256, EXPECTED_OUTPUT_SHA256 (this script)"
echo "  README.md (under fixture dir) — Provenance + Pinned Hashes section"
