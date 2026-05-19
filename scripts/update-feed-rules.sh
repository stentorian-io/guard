#!/usr/bin/env zsh
#
# Extract host IOCs from ossf/malicious-packages OSV records and write them
# to crates/sentinel-core/data/deny/ossf-malicious-packages.yaml.
#
# Requires: jq, git, shasum
# Usage: scripts/update-feed-rules.sh [--repo-dir /path/to/existing/clone]
#
# Without --repo-dir the script shallow-clones ossf/malicious-packages into a
# temporary directory (cleaned up on exit). With --repo-dir it does a fetch
# against an existing clone (CI caches the clone across runs).

set -euo pipefail

REPO_URL="https://github.com/ossf/malicious-packages.git"
OUTPUT_FILE="crates/sentinel-core/data/deny/ossf-malicious-packages.yaml"

repo_dir=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --repo-dir) repo_dir="$2"; shift 2 ;;
    *) echo "Unknown arg: $1" >&2; exit 1 ;;
  esac
done

cleanup() {
  if [[ -n "${tmpdir:-}" ]]; then
    rm -rf "$tmpdir"
  fi
}
trap cleanup EXIT

if [[ -z "$repo_dir" ]]; then
  tmpdir=$(mktemp -d)
  repo_dir="$tmpdir/malicious-packages"
  echo "Shallow-cloning ossf/malicious-packages …"
  git clone --depth 1 --single-branch --branch main \
    "$REPO_URL" "$repo_dir" 2>&1 | tail -1
else
  echo "Using existing clone at $repo_dir"
fi

echo "Extracting host IOCs …"

# Build a sorted, deduplicated list of (match_type, pattern) pairs from all
# OSV JSON files. jq does the heavy lifting per-file; we collect everything
# then dedup at the shell level.
#
# Per the old Rust parser:
#   PRIMARY:   .database_specific.iocs.domains[]   → match: exact
#              .database_specific.iocs.ips[]        → match: ip
#   SECONDARY: .references[] | select(.type == "EVIDENCE" or .type == "REPORT")
#              → extract hostname from .url          → match: exact

raw_iocs=$(find "$repo_dir" -name '*.json' -not -path '*/.git/*' -print0 \
  | xargs -0 jq -r '
    def safe_str_array: if type == "array" then .[] | select(type == "string") else empty end;

    # Advisory ID for the reason field
    (.id // "unknown") as $id |

    # Primary: domains
    ((.database_specific.iocs.domains // []) | safe_str_array
      | select(length > 0 and length <= 256)
      | "exact\t" + . + "\t" + $id),

    # Primary: IPs
    ((.database_specific.iocs.ips // []) | safe_str_array
      | select(length > 0 and length <= 256)
      | "ip\t" + . + "\t" + $id),

    # Secondary: EVIDENCE/REPORT reference URL hosts
    ((.references // [])[]
      | select(.type == "EVIDENCE" or .type == "REPORT")
      | .url // empty
      | capture("^https?://(?<host>[^/:]+)") | .host
      | select(length > 0 and length <= 256)
      | "exact\t" + . + "\t" + $id)
  ' 2>/dev/null || true)

# Deduplicate by (match_type, pattern), keeping the first advisory ID seen.
# Sort for stable diffs.
declare -A seen
declare -a entries
while IFS=$'\t' read -r match_type pattern advisory_id; do
  [[ -z "$pattern" ]] && continue
  key="${match_type}:${pattern}"
  if [[ -z "${seen[$key]:-}" ]]; then
    seen[$key]=1
    entries+=("${match_type}"$'\t'"${pattern}"$'\t'"${advisory_id}")
  fi
done <<< "$raw_iocs"

# Sort entries by pattern for stable output.
sorted_entries=("${(@f)$(printf '%s\n' "${entries[@]}" | sort -t$'\t' -k2,2)}")
# Handle empty array: if no IOCs found, sorted_entries may have one empty element
[[ ${#sorted_entries[@]} -eq 1 && -z "${sorted_entries[1]}" ]] && sorted_entries=()

ioc_count=${#sorted_entries[@]}
echo "Found $ioc_count unique host IOCs."

# Write the output file (full replace, not append).
{
  echo "# Auto-generated from ossf/malicious-packages OSV records."
  echo "# Managed by scripts/update-feed-rules.sh — do not edit manually."
  for entry in "${sorted_entries[@]}"; do
    IFS=$'\t' read -r match_type pattern advisory_id <<< "$entry"
    [[ -z "$pattern" ]] && continue
    cat <<YAML
- match: $match_type
  pattern: $pattern
  reason: "$advisory_id supply-chain IOC (FEED)"
YAML
  done
} > "$OUTPUT_FILE"

echo "Wrote $ioc_count feed IOC entries to $OUTPUT_FILE."

# Print a SHA-256 of the output file for CI audit logs.
shasum -a 256 "$OUTPUT_FILE"
